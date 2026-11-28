//! The compiled configuration.
//!
//! This is deliberately *not* the shape of the JSON. Parsing produces this,
//! and the runtime only ever sees this: immutable, string-interned where it
//! matters, with invalid protocol/transport combinations already rejected
//! (RESEARCH-01 §4, §19).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use zero_core::{Address, OutboundId};

// ---------------------------------------------------------------- transports

/// Which carrier a stream rides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Bare TCP with no framing. Xray calls this `raw` (historically `tcp`).
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(WebSocketConfig),
    Grpc(WebSocketConfig),
    /// XHTTP over HTTP/1.1, HTTP/2, or HTTP/3. HTTP/1.1 and HTTP/2 support the
    /// packet-up and stream-up split modes implemented by the carrier; HTTP/3
    /// supports stream-one, stream-up, and packet-up request streams.
    Xhttp(WebSocketConfig),
}

impl Transport {
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Raw => "raw",
            Transport::WebSocket(_) => "ws",
            Transport::HttpUpgrade(_) => "httpupgrade",
            Transport::Grpc(_) => "grpc",
            Transport::Xhttp(_) => "xhttp",
        }
    }

    /// What this carrier can support, used to reject impossible combinations
    /// at compile time rather than at connect time (RESEARCH-01 §19).
    pub fn capabilities(&self) -> CarrierCapabilities {
        match self {
            Transport::Raw => CarrierCapabilities {
                preserves_direct_stream: true,
                supports_reality: true,
                supports_vision: true,
            },
            // A WebSocket carrier hands back an HTTP wrapper, not the security
            // connection Vision needs to splice into, and Xray refuses REALITY
            // over WebSocket.
            Transport::WebSocket(_) | Transport::HttpUpgrade(_) => CarrierCapabilities {
                preserves_direct_stream: false,
                supports_reality: false,
                supports_vision: false,
            },
            // gRPC is HTTP/2, which REALITY carries as it carries XHTTP's:
            // Xray accepts REALITY over TCP, XHTTP and gRPC.
            Transport::Grpc(_) => CarrierCapabilities {
                preserves_direct_stream: false,
                supports_reality: true,
                supports_vision: false,
            },
            Transport::Xhttp(settings) => CarrierCapabilities {
                preserves_direct_stream: false,
                // REALITY is a TLS stream and can carry XHTTP H1/H2 after
                // its handshake. HTTP/3 has a separate QUIC TLS path and is
                // intentionally kept on ordinary certificate TLS.
                supports_reality: settings.xhttp_http_version != XhttpHttpVersion::Http3,
                supports_vision: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierCapabilities {
    pub preserves_direct_stream: bool,
    pub supports_reality: bool,
    pub supports_vision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebSocketConfig {
    pub path: Arc<str>,
    /// Value for the `Host:` header; may differ from the TLS SNI.
    pub host: Option<Arc<str>>,
    pub headers: BTreeMap<Box<str>, Box<str>>,
    /// Max bytes of payload carried in `Sec-WebSocket-Protocol` on the
    /// handshake request, saving a round trip. From `?ed=N` in the path.
    pub early_data_len: usize,
    /// XHTTP's upload mode. Ignored by WebSocket and HTTPUpgrade carriers.
    pub xhttp_mode: XhttpMode,
    /// HTTP version selected for XHTTP. H1/H2 stream-one, packet-up, and
    /// stream-up are real carriers; H3 stream-one/stream-up/packet-up are real
    /// carriers.
    pub xhttp_http_version: XhttpHttpVersion,
    /// Optional independent XHTTP download endpoint. The nested stream is
    /// compiled with the same strict security checks as the upload stream.
    pub xhttp_download: Option<Box<XhttpDownloadConfig>>,
    /// XHTTP padding, placement and upload settings (Xray's
    /// `xhttpSettings`, or its `extra`).
    pub xhttp: crate::xhttp::XhttpSettings,
    /// gRPC only: the path of the `TunMulti` method when it differs from
    /// `path`; a server serves both, and the path of a request says which.
    pub grpc_multi_path: Option<Arc<str>>,
    /// gRPC only (Xray's `multiMode`): a client frames its stream as
    /// `MultiHunk` and calls the multi method.
    pub grpc_multi: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpDownloadConfig {
    pub address: Address,
    pub port: u16,
    pub stream: Box<StreamSettings>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    #[default]
    StreamOne,
}

impl XhttpMode {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Self::Auto,
            "packet-up" => Self::PacketUp,
            "stream-up" => Self::StreamUp,
            "stream-one" => Self::StreamOne,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpHttpVersion {
    #[default]
    Http1,
    Http2,
    Http3,
}

// ----------------------------------------------------------------- security

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    None,
    Tls(TlsConfig),
    Reality(RealityConfig),
    ShadowTls(ShadowTlsConfig),
}

impl Security {
    pub fn name(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls(_) => "tls",
            Security::Reality(_) => "reality",
            Security::ShadowTls(_) => "shadowtls",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsConfig {
    pub server_name: Option<Arc<str>>,
    pub alpn: Vec<Box<str>>,
    pub fingerprint: Fingerprint,
    /// Xray's `allowInsecure`: accept any certificate. Set only by a link or
    /// config that asks for it, never by default.
    pub allow_insecure: bool,
    /// Explicit ECH configuration and the inner SNI to encrypt. The outer
    /// public name is carried by the ECHConfigList itself.
    pub ech: Option<EchConfig>,
    /// Additional trust anchors, from `certificates` entries with
    /// `usage: "verify"`. This is the supported way to reach a server whose
    /// certificate is issued by a private CA. Unlike `allowInsecure` it does
    /// not weaken anything: the chain is still verified and the name still has
    /// to match — the operator has simply named an extra issuer to trust.
    pub trusted_roots: Vec<Box<[u8]>>,
    /// Xray's `pinnedPeerCertSha256` (`pcs=` in links): SHA-256 hashes of
    /// certificates the server must present. A hash that matches the leaf is
    /// accepted outright; one that matches a certificate further up the chain
    /// still needs the chain and name to verify; no match at all is refused.
    /// Empty means no pinning.
    pub pinned_cert_sha256: Vec<[u8; 32]>,
    /// Xray's `verifyPeerCertByName`: the names the server's certificate may
    /// carry in place of the server name sent. Empty verifies for the name
    /// sent.
    pub verify_names: Vec<Box<str>>,
    /// Xray's `masterKeyLog`: a file the session secrets are appended to for
    /// Wireshark. Anyone who can read it can decrypt the traffic.
    pub key_log_file: Option<Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// TLS-encoded ECHConfigList bytes after base64 decoding.
    pub config_list: Box<[u8]>,
    /// Inner SNI. When omitted, the ordinary TLS `serverName` is used.
    pub server_name: Option<Arc<str>>,
    /// The name whose HTTPS record carries the list, when `config_list` is
    /// empty and has to be looked up. Omitted means the TLS `serverName`.
    /// Xray's `cloudflare-ech.com+udp://1.1.1.1` names it before the `+`:
    /// Cloudflare serves one list for every site it hosts, so a site with
    /// no record of its own can still use it.
    pub query_name: Option<Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub server_name: Arc<str>,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: Fingerprint,
    pub spider_x: Option<Arc<str>>,
    /// Optional ML-DSA-65 public key used for the second REALITY
    /// certificate-binding check. Xray encodes this as 1952 raw bytes in
    /// `realitySettings.mldsa65Verify`.
    pub mldsa65_verify: Option<Box<[u8]>>,
}

/// ShadowTLS v3 settings.
///
/// ShadowTLS wraps an inner protocol (always Shadowsocks here) in a stream that
/// looks like an ordinary TLS session to a decoy site. The client proves itself
/// with `password` keyed into the ClientHello, and presents `server_name` as
/// the decoy SNI. `alpn` is carried into the ClientHello for camouflage only;
/// it never changes which protocol rides inside. Only version 3 is supported,
/// so there is no version field — a non-3 config is rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowTlsConfig {
    pub password: Arc<str>,
    pub server_name: Arc<str>,
    pub alpn: Vec<Box<str>>,
}

/// uTLS ClientHello shape. A stock Rust TLS hello is itself a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Fingerprint {
    #[default]
    Chrome,
    Firefox,
    Safari,
    Edge,
    Ios,
    Android,
    Random,
    Randomized,
    /// One of the concrete Xray/uTLS profile names from the embedded corpus.
    Named(Arc<str>),
    /// No shaping; use the TLS backend's native hello.
    Unshaped,
}

impl Fingerprint {
    pub fn parse(s: &str) -> Option<Self> {
        let normalized = s.trim().to_ascii_lowercase();
        Some(match normalized.as_str() {
            "chrome" => Fingerprint::Chrome,
            "firefox" => Fingerprint::Firefox,
            "safari" => Fingerprint::Safari,
            "edge" => Fingerprint::Edge,
            "ios" => Fingerprint::Ios,
            "android" => Fingerprint::Android,
            "random" => Fingerprint::Random,
            "randomized" => Fingerprint::Randomized,
            "" | "none" | "unshaped" => Fingerprint::Unshaped,
            name if XRAY_PROFILE_NAMES.contains(&name) => Fingerprint::Named(Arc::from(normalized)),
            _ => return None,
        })
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Edge => "edge",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Random => "random",
            Self::Randomized => "randomized",
            Self::Named(name) => name,
            Self::Unshaped => "unshaped",
        }
    }

    /// REALITY requires an X25519 key share in the hello. Profiles that do not
    /// carry one cannot be used with it.
    ///
    /// The family aliases are not exempt: `android` resolves to exactly the
    /// same okhttp shape as `helloandroid_11_okhttp`, so refusing one and
    /// accepting the other would let the same impossible combination through
    /// under its shorter name. `random` and `randomized` are allowed because
    /// every name they can draw carries the share; the REALITY parity test in
    /// `zero-runtime` holds that claim to the corpus.
    pub fn supports_reality(&self) -> bool {
        match self {
            Self::Unshaped | Self::Android => false,
            Self::Named(name) => !REALITY_UNSUPPORTED_PROFILE_NAMES.contains(&name.as_ref()),
            _ => true,
        }
    }
}

// Keep this list local to zero-config so a config is rejected at compile time
// rather than failing later in the TLS backend. The corresponding concrete
// shapes live in zero-security's product-owned Xray profile corpus.
const XRAY_PROFILE_NAMES: &[&str] = &[
    "hellochrome_auto",
    "hellochrome_133",
    "hellochrome_155",
    "hellofirefox_auto",
    "hellofirefox_148",
    "hellosafari_auto",
    "hellosafari_26_3",
    "helloios_14",
    "helloios_auto",
    "helloandroid_11_okhttp",
    "helloedge_85",
    "helloedge_auto",
    "360",
    "hello360_auto",
    "hello360_7_5",
    "qq",
    "helloqq_11_1",
    "helloqq_auto",
    "hellorandomized",
    "randomizednoalpn",
    "hellorandomizednoalpn",
    "hellofirefox_120",
    "hellochrome_120",
    "hellochrome_131",
    "helloios_13",
    "helloedge_106",
    "hello360_11_0",
    "hellorandomizedalpn",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_58",
    "hellochrome_62",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "helloios_11_1",
    "helloios_12_1",
    "hellosafari_16_0",
    "hellochrome_100_psk",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

const REALITY_UNSUPPORTED_PROFILE_NAMES: &[&str] = &[
    "android",
    "360",
    "hello360_auto",
    "hello360_7_5",
    "randomizednoalpn",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellochrome_58",
    "hellochrome_62",
    "helloios_11_1",
    "helloios_12_1",
    "helloandroid_11_okhttp",
];

// ----------------------------------------------------------------- evasion

/// `streamSettings.finalmask` — active DPI evasion.
///
/// Defaults follow BPB's field-tuned values (PLAN-02 §3.1-3.2); they are a
/// starting prior for the observatory, not constants.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evasion {
    pub tcp_fragment: Option<FragmentConfig>,
    /// A second fragment mask underneath the first: it cuts up what the
    /// first one writes. Xray stacks the masks of `finalmask.tcp` this way,
    /// the later entry on top, and the recipes that pair an empty record
    /// with a TCP split need both. Never set without `tcp_fragment`.
    pub tcp_fragment_under: Option<FragmentConfig>,
    pub udp_noise: Vec<NoiseConfig>,
    /// Salamander obfuscation of every UDP datagram of a QUIC carrier
    /// (`finalmask.udp` `salamander`): the password both ends share.
    pub udp_salamander: Option<Box<str>>,
    /// Move a QUIC carrier's server port over time (`udphop`).
    pub udp_hop: Option<UdpHop>,
    /// QUIC transport settings (`finalmask.quicParams`).
    pub quic: Option<QuicParams>,
    /// Optional Linux raw-packet fake-SNI injection selected by the planner.
    pub sni_desync: Option<SniDesyncConfig>,
    /// Optional keepalive shaping for a network that resets flows on a time
    /// threshold rather than a byte threshold (PLAN-01 §5.2).
    pub keepalive: Option<KeepaliveConfig>,
}

impl Evasion {
    /// Whether any shaping other than the UDP/QUIC kind is set: what a QUIC
    /// carrier cannot take (TCP fragments, noise, SNI tricks, keepalive
    /// probes). Salamander, port hopping and QUIC parameters are the shaping
    /// it does take.
    pub fn has_non_quic_shaping(&self) -> bool {
        self.tcp_fragment.is_some()
            || self.tcp_fragment_under.is_some()
            || !self.udp_noise.is_empty()
            || self.sni_desync.is_some()
            || self.keepalive.is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.tcp_fragment.is_none()
            && self.tcp_fragment_under.is_none()
            && self.udp_noise.is_empty()
            && self.udp_salamander.is_none()
            && self.udp_hop.is_none()
            && self.quic.is_none()
            && self.sni_desync.is_none()
            && self.keepalive.is_none()
    }
}

/// Port hopping for a UDP carrier: the client sends to a different server
/// port every so often, picked from `ports`, while the QUIC connection above
/// it carries on unchanged. A filter that blocks one UDP flow by its port
/// pair sees it end and a new one begin. The server side is a port range that
/// forwards to one listening port (a firewall redirect), as Hysteria's is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHop {
    /// Server ports to choose from, in the order given.
    pub ports: Vec<crate::routing::PortRange>,
    /// Seconds between moves, drawn at random from this range each time
    /// (Xray's minimum is 5).
    pub interval_secs: (u32, u32),
}

impl UdpHop {
    /// Every port the ranges cover, without repeats.
    pub fn all_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.ports.iter().flat_map(|r| r.start..=r.end).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// How a QUIC carrier controls its sending rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicCongestion {
    /// What the protocol defaults to: Hysteria 2 negotiates its rate with the
    /// peer, the others use BBR.
    #[default]
    Default,
    Reno,
    Bbr,
    /// Send at the configured rate whatever the loss, if the peer agreed.
    Brutal,
    /// Send at the configured rate whether or not the peer agreed.
    ForceBrutal,
}

/// Xray's `finalmask.quicParams`. Every field unset means "as before".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuicParams {
    pub congestion: QuicCongestion,
    /// Bytes per second the client may send at under brutal; 0 = unlimited
    /// (BBR instead).
    pub up_bytes_per_sec: u64,
    /// Bytes per second the client asks the server to send at; 0 = unknown.
    pub down_bytes_per_sec: u64,
    pub init_stream_window: Option<u32>,
    pub max_stream_window: Option<u32>,
    pub init_connection_window: Option<u32>,
    pub max_connection_window: Option<u32>,
    pub max_idle_secs: Option<u32>,
    pub keep_alive_secs: Option<u32>,
    pub disable_mtu_discovery: bool,
    pub max_incoming_streams: Option<u32>,
}

/// Shaping for a flow-timeout policy: keep an idle carrier from looking
/// abandoned, and retire it before the middlebox does.
///
/// Both halves are needed because the two observed behaviours are different.
/// A middlebox that collects *idle* flows is answered by probing; one that
/// expires *every* flow at a fixed age is answered only by rotating ahead of
/// it, however busy the flow is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// Emit one carrier no-op after this much silence.
    pub idle_after: Duration,
    /// Stop handing new sessions to a carrier this old. `None` never retires.
    pub max_flow_lifetime: Option<Duration>,
}

impl Default for KeepaliveConfig {
    /// A conservative shape for a network that has shown a flow timeout but
    /// not yet said where it is. The planner replaces these with values sized
    /// from the actual observation as soon as it has one.
    fn default() -> Self {
        Self {
            idle_after: Duration::from_secs(15),
            max_flow_lifetime: Some(Duration::from_secs(120)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniDesyncConfig {
    pub fake_sni: Box<str>,
    pub sequence: u32,
    /// Which way the name is kept from the filter.
    pub method: SniMethod,
    /// How a decoy is kept from the server (`zero_evasion::Fooling`).
    pub fooling: DecoyFooling,
    /// The hop limit for a decoy stopped by expiry, as a static guess. Zero
    /// means none is configured; the runtime may still learn one from the
    /// path at connection time (`zero_evasion::autottl`), and only where it
    /// cannot does a device without the MD5 option fall back to the urgent
    /// byte. A guess that reaches the server is worse than none.
    pub ttl: u8,
}

/// What keeps a decoy ClientHello from the server it is addressed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecoyFooling {
    /// The MD5 option where the kernel has it, otherwise the TTL when one is
    /// given, otherwise no decoy.
    #[default]
    Auto,
    /// The MD5 option only.
    Md5,
    /// A hop limit that expires between the filter and the server, for a
    /// kernel without the MD5 option. Needs `ttl`.
    Ttl,
}

/// The ways of keeping a server name from a filter that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SniMethod {
    /// The urgent byte, which costs nothing, and a decoy ClientHello only
    /// towards a server the urgent byte went unanswered at, or where the
    /// device cannot send the urgent byte (`zero_evasion::choice`). What a
    /// configuration gets when it names none.
    #[default]
    Auto,
    /// A decoy ClientHello naming `fake_sni`, sent ahead of the real one
    /// (`zero_evasion::decoy`, or a raw packet where the process may send
    /// one). Works against the most filters; adds a resend to every
    /// connection and needs a kernel feature or a raw socket.
    Decoy,
    /// One byte of TCP urgent data in the middle of the name
    /// (`zero_evasion::urgent`). No delay and no kernel feature; `fake_sni`
    /// is not used.
    Urgent,
    /// The hello rides in the SYN (TCP Fast Open, `zero_net::fastopen`), so a
    /// filter that reads the stream after the handshake never sees the name.
    /// No delay and no privilege; needs a kernel with `TCP_FASTOPEN_CONNECT`
    /// and a server that does Fast Open, and only applies to ports where the client speaks first (443, 80 and the like).
    /// `fake_sni` is not used.
    FastOpen,
    /// The first record header and the hello's own `legacy_version` carry
    /// 0x0304 instead of 0x0301 and 0x0303 (`zero_evasion::record`, and the
    /// TLS layer on top for the second): a filter that only parses records
    /// and hellos of the usual versions sees no name, and servers read the
    /// hello as usual. The first alone is all a plain relay (`direct://`)
    /// can do. No delay, no privilege and no kernel feature; `fake_sni` is
    /// not used.
    Record,
    /// One empty handshake record ahead of the hello
    /// (`zero_evasion::record`): the filter reads it as the start of the
    /// stream and gives up on the next record; servers skip it. Needs nothing
    /// from the system; `fake_sni` is not used.
    EmptyRecord,
}

impl SniDesyncConfig {
    /// The urgent-byte method, for the callers that try it as a way of its
    /// own (the CDN check, the server test).
    pub fn urgent() -> Self {
        Self {
            method: SniMethod::Urgent,
            ..Self::default()
        }
    }

    /// The record-version method and nothing else.
    pub fn record() -> Self {
        Self {
            method: SniMethod::Record,
            ..Self::default()
        }
    }

    /// The empty-record method and nothing else.
    pub fn empty_record() -> Self {
        Self {
            method: SniMethod::EmptyRecord,
            ..Self::default()
        }
    }

    /// The Fast Open method and nothing else.
    pub fn fast_open() -> Self {
        Self {
            method: SniMethod::FastOpen,
            ..Self::default()
        }
    }

    /// The decoy method and nothing else.
    pub fn decoy() -> Self {
        Self {
            method: SniMethod::Decoy,
            ..Self::default()
        }
    }
}

impl Default for SniDesyncConfig {
    fn default() -> Self {
        Self {
            fake_sni: "www.speedtest.net".into(),
            sequence: 0,
            method: SniMethod::Auto,
            fooling: DecoyFooling::Auto,
            ttl: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentConfig {
    pub packets: FragmentPackets,
    /// Bytes per fragment.
    pub length: RangeU32,
    /// Delay between fragments.
    pub delay: RangeDuration,
    /// Upper bound on fragment count; `0` means unlimited.
    pub max_split: RangeU32,
    /// Zero-length TLS records put in front of the ClientHello. Only
    /// [`FragmentPackets::TlsHello`] can do this; see [`Self::empty_record`].
    pub empty_records: u8,
    /// Sizes for the first pieces after any empty records, one entry per
    /// piece; `length` sizes the pieces after them. Together with the
    /// leading zeros counted in `empty_records` this is Xray's `lengths`.
    pub lead_lengths: Vec<RangeU32>,
    /// Delays after the first pieces, counted from the very first one, one
    /// entry per piece; `delay` follows the pieces after them. Xray's
    /// `delays`. With any entry here the records are never merged into one
    /// write, as in Xray.
    pub lead_delays: Vec<RangeDuration>,
}

impl FragmentConfig {
    /// One empty TLS record, then the ClientHello whole, in a single write.
    ///
    /// A filter that reads the server name out of the first record of a
    /// connection finds a record with nothing in it and lets the rest go.
    /// Measured 2026-10-07 from Center (Zi-Tel) against Cloudflare's edge:
    /// names that are dropped as is (`api.cloudflareclient.com`,
    /// `*.pages.dev`) completed the handshake 2 of 2 this way, while TCP
    /// segments of 40 bytes and plain record re-framing got 0 of 2. It costs
    /// five bytes and no delay. Cloudflare accepts the empty record; not
    /// every server does, so it is something to try, not to assume.
    ///
    /// The empty record says 0x0303 in its header, not the hello's 0x0301
    /// (`zero_evasion::fragment`): measured 2026-10-13 on the same kind of
    /// line, the 0x0301 form got nothing back from Cloudflare, Fastly or
    /// Google and the 0x0303 form got through to all three.
    pub fn empty_record() -> Self {
        Self {
            packets: FragmentPackets::TlsHello,
            // Larger than any ClientHello, so the hello stays one record.
            length: RangeU32::new(16_384, 16_384),
            // No delay keeps both records in one write, which is what works:
            // the empty record sent on its own got 0 of 2.
            delay: RangeDuration::millis(0, 0),
            max_split: RangeU32::new(0, 0),
            empty_records: 1,
            lead_lengths: Vec::new(),
            lead_delays: Vec::new(),
        }
    }

    /// Split the ClientHello into two TLS records with the cut inside the
    /// server name, both in one write.
    ///
    /// A filter that reads the name out of the first TLS record of a
    /// connection, after putting the TCP segments back together, finds only a
    /// piece of it. The name's second-level label is where a suffix match
    /// keys, so the cut is aimed there (`speedtest` in `www.speedtest.net`).
    /// It costs five bytes and no delay, and the server reassembles the two
    /// records into the one hello as it would any split handshake message.
    pub fn sni_split() -> Self {
        Self {
            packets: FragmentPackets::TlsSni,
            // `length` is unused for this mode; the cut comes from the name.
            length: RangeU32::new(16_384, 16_384),
            // No delay keeps both records in one write.
            delay: RangeDuration::millis(0, 0),
            max_split: RangeU32::new(0, 0),
            empty_records: 0,
            lead_lengths: Vec::new(),
            lead_delays: Vec::new(),
        }
    }
}

impl Default for FragmentConfig {
    fn default() -> Self {
        // Plain TCP segments of the first write, 40-80 bytes, 1 ms apart.
        // Measured 2026-09-28 from Center (FANAP) against a throttled
        // workers.dev edge: `tlshello` record re-framing got 0 of 3 through,
        // this got 3 of 3; with no gap the pieces coalesce into one segment
        // and fail, and pieces of 200+ bytes got 1 of 3.
        Self {
            packets: FragmentPackets::Range { from: 1, to: 1 },
            length: RangeU32::new(40, 80),
            delay: RangeDuration::millis(1, 1),
            max_split: RangeU32::new(0, 0),
            empty_records: 0,
            lead_lengths: Vec::new(),
            lead_delays: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPackets {
    /// Fragment only the TLS ClientHello — cheapest and the BPB default.
    TlsHello,
    /// Fragment only the TLS ClientHello, with a record cut inside the server
    /// name (`zero_evasion::fragment::plan_tls_sni`). For a filter that
    /// reassembles TCP but reads the name from a single TLS record.
    TlsSni,
    /// Fragment writes `from..=to` counting from the first write.
    Range { from: u32, to: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseConfig {
    pub kind: NoiseKind,
    pub delay: RangeDuration,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseKind {
    /// Random bytes, with a length range.
    Rand {
        length: RangeU32,
        byte_range: (u8, u8),
    },
    Str(Box<str>),
    Hex(Vec<u8>),
    Base64(Vec<u8>),
    Array(Vec<u8>),
    /// A syntactically plausible QUIC Initial-shaped decoy packet.
    Quic {
        length: RangeU32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeU32 {
    pub min: u32,
    pub max: u32,
}

impl RangeU32 {
    pub fn new(min: u32, max: u32) -> Self {
        Self {
            min,
            max: max.max(min),
        }
    }

    /// Parse `"N"` or `"MIN-MAX"`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            Some(Self::new(a.trim().parse().ok()?, b.trim().parse().ok()?))
        } else {
            let v = s.parse().ok()?;
            Some(Self::new(v, v))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeDuration {
    pub min: Duration,
    pub max: Duration,
}

impl RangeDuration {
    pub fn millis(min: u64, max: u64) -> Self {
        Self {
            min: Duration::from_millis(min),
            max: Duration::from_millis(max.max(min)),
        }
    }

    pub fn parse_millis(s: &str) -> Option<Self> {
        let r = RangeU32::parse(s)?;
        Some(Self::millis(r.min as u64, r.max as u64))
    }
}

// ----------------------------------------------------------------- sockopt

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sockopt {
    pub domain_strategy: DomainStrategy,
    pub tcp_fast_open: bool,
    pub happy_eyeballs: Option<HappyEyeballs>,
    pub dialer_proxy: Option<Arc<str>>,
    pub mark: Option<u32>,
    pub bind_interface: Option<Arc<str>>,
    /// Named TCP congestion algorithm for this outbound's sockets, where the
    /// kernel supports them (`TCP_CONGESTION` on Linux).
    ///
    /// Carried as a name rather than an enum because the set is the kernel's,
    /// not ours: an algorithm this build has never heard of is a request the
    /// dial either honours or declines at `setsockopt` time, and `None` here
    /// means "leave the system default alone" — which is also the honest
    /// answer on a platform with no such sockopt at all.
    pub tcp_congestion: Option<Arc<str>>,
    /// Seconds idle before TCP keepalive probes and between them (Xray's
    /// `tcpKeepAliveIdle` and `tcpKeepAliveInterval`, each 45 when unset or
    /// 0). `Some((0, 0))` turns keepalive off (Xray: a negative number).
    pub keepalive: Option<(u32, u32)>,
    /// `tcpUserTimeout`, in milliseconds.
    pub user_timeout_ms: Option<u32>,
    /// `tcpWindowClamp`: the largest receive window advertised.
    pub window_clamp: Option<u32>,
    /// `tcpMaxSeg`: the segment size to send.
    pub max_seg: Option<u32>,
    /// `tcpMptcp`: Multipath TCP where the kernel has it.
    pub mptcp: bool,
    /// `V6Only`, for an inbound listening on `::`.
    pub v6_only: Option<bool>,
    /// Xray's `tproxy`: how a gateway steers traffic into this inbound.
    pub tproxy: Tproxy,
    /// Xray's `customSockopt`: raw `setsockopt` calls on this socket.
    pub custom: Vec<zero_core::custom_sockopt::CustomSockopt>,
    /// Xray's `sendThrough`: the local address this outbound's connections
    /// leave from, on a host with several. A connection to a server of the
    /// other IP family leaves from the system's choice.
    pub bind_address: Option<std::net::IpAddr>,
}

/// How traffic reaches a transparent inbound (Xray's `sockopt.tproxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tproxy {
    #[default]
    Off,
    /// `iptables -j REDIRECT`: the original destination comes from the
    /// kernel's connection tracking. TCP only.
    Redirect,
    /// `TPROXY`: the listener is `IP_TRANSPARENT` and sees the real
    /// destination as its local address. TCP and UDP.
    Tproxy,
}

impl Tproxy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "off" | "" => Tproxy::Off,
            "redirect" => Tproxy::Redirect,
            "tproxy" => Tproxy::Tproxy,
            _ => return None,
        })
    }
}

impl Default for Sockopt {
    fn default() -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            tcp_fast_open: false,
            happy_eyeballs: None,
            dialer_proxy: None,
            mark: None,
            bind_interface: None,
            tcp_congestion: None,
            keepalive: None,
            user_timeout_ms: None,
            window_clamp: None,
            max_seg: None,
            mptcp: false,
            v6_only: None,
            tproxy: Tproxy::Off,
            custom: Vec::new(),
            bind_address: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    UseIp,
    UseIpv4,
    UseIpv6,
    PreferIpv4,
    PreferIpv6,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "asis" => DomainStrategy::AsIs,
            "useip" | "useipv4v6" => DomainStrategy::UseIp,
            "useipv4" => DomainStrategy::UseIpv4,
            "useipv6" => DomainStrategy::UseIpv6,
            "preferipv4" => DomainStrategy::PreferIpv4,
            "preferipv6" => DomainStrategy::PreferIpv6,
            _ => return None,
        })
    }

    pub fn wants_ipv4(self) -> bool {
        !matches!(self, DomainStrategy::UseIpv6)
    }

    pub fn wants_ipv6(self) -> bool {
        !matches!(self, DomainStrategy::UseIpv4)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HappyEyeballs {
    pub try_delay: Duration,
    pub prioritize_ipv6: bool,
    /// Address-family chunk size when interleaving candidates; `0` exhausts
    /// the preferred family first.
    pub interleave: u32,
    pub max_concurrent: u32,
}

impl Default for HappyEyeballs {
    fn default() -> Self {
        Self {
            try_delay: Duration::from_millis(250),
            prioritize_ipv6: false,
            interleave: 2,
            max_concurrent: 4,
        }
    }
}

// ---------------------------------------------------------------- outbounds

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettings {
    pub transport: Transport,
    pub security: Security,
    pub sockopt: Sockopt,
    pub evasion: Evasion,
    /// Optional Xray raw/TCP HTTP camouflage header. This is a one-time
    /// request/response exchange around the protocol stream, not an HTTP
    /// proxy and not a second carrier.
    pub raw_http_header: Option<RawHttpHeader>,
    /// What a Freedom outbound does with the destination before and after it
    /// connects. `None` for every other protocol, and for a plain Freedom.
    pub direct: Option<Arc<DirectPolicy>>,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            transport: Transport::Raw,
            security: Security::None,
            sockopt: Sockopt::default(),
            evasion: Evasion::default(),
            raw_http_header: None,
            direct: None,
        }
    }
}

/// The parts of Xray's `freedom` outbound beyond fragmenting and noise:
/// where a connection is redirected, whether a PROXY protocol header is
/// sent, and which final destinations are allowed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectPolicy {
    /// Replace the destination's address and/or port before connecting.
    pub redirect: Option<DirectRedirect>,
    /// 1 or 2: send a PROXY protocol header of that version first (so a
    /// backend behind the server learns the client's address). 0 sends none.
    pub proxy_protocol: u8,
    /// Checked against every address the destination resolves to; the first
    /// rule that matches decides, and an address no rule matches is allowed.
    pub final_rules: Box<[FinalRule]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRedirect {
    pub address: Option<Address>,
    pub port: Option<u16>,
}

/// One entry of Freedom's `finalRules`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalRule {
    pub allow: bool,
    /// Empty means every network.
    pub networks: Vec<zero_core::Network>,
    /// Empty means every port.
    pub ports: Vec<crate::routing::PortRange>,
    /// Empty means every address. Only CIDR ranges and `geoip:private`.
    pub ips: Vec<crate::routing::IpPattern>,
    /// How long a blocked connection is held before it is dropped, as a
    /// range in seconds, so a prober learns nothing from the timing.
    pub block_delay_secs: (u32, u32),
}

impl FinalRule {
    /// Whether this rule applies to a connection to `ip:port` over `network`.
    pub fn matches(&self, network: zero_core::Network, ip: std::net::IpAddr, port: u16) -> bool {
        use crate::routing::IpPattern;
        // An IPv4 address written as ::ffff:a.b.c.d is that IPv4 address.
        let ip = match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4),
            other => other,
        };
        (self.networks.is_empty() || self.networks.contains(&network))
            && (self.ports.is_empty() || self.ports.iter().any(|range| range.contains(port)))
            && (self.ips.is_empty()
                || self.ips.iter().any(|pattern| match pattern {
                    IpPattern::Cidr(cidr) => cidr.contains(ip),
                    IpPattern::Private => is_private_or_reserved(ip),
                    IpPattern::Geoip(_) => false,
                }))
    }
}

impl DirectPolicy {
    /// The rule that decides for this connection, if any matches.
    pub fn decide(
        &self,
        network: zero_core::Network,
        ip: std::net::IpAddr,
        port: u16,
    ) -> Option<&FinalRule> {
        self.final_rules
            .iter()
            .find(|rule| rule.matches(network, ip, port))
    }
}

/// Loopback, private, link-local, shared, documentation, multicast and
/// otherwise reserved addresses: where a proxy's own network and its cloud
/// provider's metadata service live.
pub fn is_private_or_reserved(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15
                || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
                || o[0] >= 240 // 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 well-known prefix
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpHeader {
    pub request: RawHttpRequest,
    pub response: Option<RawHttpResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpRequest {
    pub version: Box<str>,
    pub method: Box<str>,
    pub path: Box<str>,
    pub headers: BTreeMap<Box<str>, Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpResponse {
    pub version: Box<str>,
    pub status: u16,
    pub reason: Box<str>,
    pub headers: BTreeMap<Box<str>, Box<str>>,
}

/// What the `dns` outbound does with a query (Xray's `dns` outbound `rules`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAction {
    /// Answer it from the runtime's own resolver (the default for A and AAAA).
    Hijack,
    /// Give no answer at all.
    Drop,
    /// Answer with an empty response carrying this result code.
    Return(u8),
}

/// One rule of the `dns` outbound; the first that matches decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOutboundRule {
    pub action: DnsAction,
    /// Query types it covers (1 = A, 28 = AAAA, 65 = HTTPS); empty is any.
    pub qtypes: Box<[u16]>,
    /// Names it covers; empty is any.
    pub domains: Box<[crate::routing::DomainPattern]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Freedom {
        domain_strategy: DomainStrategy,
    },
    /// Refuses the connection, or answers it with `response` first (Xray's
    /// `blackhole` `response`: `http` is a bodiless 403, `custom` is bytes
    /// from the config).
    Blackhole {
        response: Option<Arc<[u8]>>,
    },
    /// Hijacks DNS queries routed to it, treating each as its `rules` say.
    Dns {
        rules: Box<[DnsOutboundRule]>,
    },
    /// Sends the connection back through routing as if it had arrived on the
    /// inbound with this tag (Xray's `loopback`): a second look with that
    /// inbound's rules, for example after a first rule has sent it through a
    /// tunnel whose own destination should be routed again.
    Loopback {
        inbound_tag: Arc<str>,
    },
    /// The public end of a reverse proxy (Xray's `reverse.portals`): what is
    /// routed here leaves through a bridge that has dialled in, and the
    /// bridge's own dial-in (addressed to `domain`) is how it registers.
    Portal {
        domain: Arc<str>,
    },
    Vless(VlessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    Vmess(VmessConfig),
    /// AnyTLS v2 over ordinary certificate TLS.
    AnyTls(AnyTlsConfig),
    /// A SOCKS5 upstream: a local Tor, Orbot or Psiphon client, or any other
    /// SOCKS5 server. TCP only.
    Socks(SocksConfig),
    /// The Tor network, through the embedded Arti client (needs a build with
    /// the `tor` feature; without it connections fail with a message saying so).
    /// TCP only. It has no endpoint of its own: the circuit's far end is the
    /// destination.
    Tor(TorConfig),
    /// A MasterDnsVPN server, reached through ordinary DNS resolvers: the
    /// traffic is carried in DNS questions and answers under a domain the
    /// server is the authority for. TCP only. Like Tor it has no endpoint of its
    /// own: the resolvers are the way in, the destination is where the server
    /// connects.
    MasterDns(MasterDnsConfig),
    /// ZeroV1 (code name Tide): sessions carried in HTTP/2 request and
    /// response bodies.
    Tide(TideConfig),
    /// Hysteria2 TCP over QUIC/HTTP3.
    Hysteria2(Hysteria2Config),
    /// TUIC v5 over authenticated QUIC.
    Tuic(TuicConfig),
    /// Juicity over authenticated QUIC. Like TUIC it rides one QUIC
    /// connection per server, but each proxied request is a trojan-style
    /// stream (`[network][addr][port]`) rather than a datagram, so UDP is
    /// carried over a stream too.
    Juicity(JuicityConfig),
    /// WireGuard/AmneziaWG UDP tunnel. TCP destinations are rejected at the
    /// runtime boundary because this protocol carries IP packets, not a byte
    /// stream.
    AmneziaWireguard(AmneziaWireguardConfig),
}

impl OutboundProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            OutboundProtocol::Freedom { .. } => "freedom",
            OutboundProtocol::Blackhole { .. } => "blackhole",
            OutboundProtocol::Dns { .. } => "dns",
            OutboundProtocol::Loopback { .. } => "loopback",
            OutboundProtocol::Portal { .. } => "portal",
            OutboundProtocol::Vless(_) => "vless",
            OutboundProtocol::Trojan(_) => "trojan",
            OutboundProtocol::Shadowsocks(_) => "shadowsocks",
            OutboundProtocol::Vmess(_) => "vmess",
            OutboundProtocol::AnyTls(_) => "anytls",
            OutboundProtocol::Socks(k) if k.http => "http",
            OutboundProtocol::Socks(_) => "socks",
            OutboundProtocol::Tor(_) => "tor",
            OutboundProtocol::MasterDns(_) => "masterdns",
            OutboundProtocol::Tide(_) => "zerov1",
            OutboundProtocol::Hysteria2(_) => "hysteria2",
            OutboundProtocol::Tuic(_) => "tuic",
            OutboundProtocol::Juicity(_) => "juicity",
            OutboundProtocol::AmneziaWireguard(_) => "amnezia-wg",
        }
    }

    /// Whether this protocol opens a remote connection of its own.
    pub fn is_proxy(&self) -> bool {
        matches!(
            self,
            OutboundProtocol::Vless(_)
                | OutboundProtocol::Trojan(_)
                | OutboundProtocol::Shadowsocks(_)
                | OutboundProtocol::Vmess(_)
                | OutboundProtocol::AnyTls(_)
                | OutboundProtocol::Socks(_)
                | OutboundProtocol::Tor(_)
                | OutboundProtocol::MasterDns(_)
                | OutboundProtocol::Tide(_)
                | OutboundProtocol::Hysteria2(_)
                | OutboundProtocol::Tuic(_)
                | OutboundProtocol::Juicity(_)
                | OutboundProtocol::AmneziaWireguard(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessConfig {
    pub address: Address,
    pub port: u16,
    pub uuid: [u8; 16],
    pub flow: Flow,
    /// `none`, or Xray's post-quantum VLESS Encryption
    /// (`mlkem768x25519plus...`, see [`is_vless_encryption`]).
    pub encryption: Box<str>,
    /// Xray's `testseed` for Vision's padding (four numbers; see
    /// `zero_protocol::vision::VisionSeed`). `None` is the defaults.
    pub vision_seed: Option<[u32; 4]>,
}

impl VlessConfig {
    /// Whether this outbound uses VLESS Encryption.
    pub fn encrypted(&self) -> bool {
        self.encryption.as_ref() != "none"
    }
}

/// Xray's syntax check for a VLESS `encryption` value
/// (`VLessOutboundConfig.Build`): `mlkem768x25519plus`, a mode
/// (`native`/`xorpub`/`random`), an RTT (`1rtt`/`0rtt`), optional padding
/// groups, then base64url keys of 32 (X25519) or 1184 (ML-KEM-768) bytes.
pub fn is_vless_encryption(value: &str) -> bool {
    use base64::Engine;
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 4
        || parts[0] != "mlkem768x25519plus"
        || !matches!(parts[1], "native" | "xorpub" | "random")
        || !matches!(parts[2], "1rtt" | "0rtt")
    {
        return false;
    }
    let mut keys = 0;
    for token in &parts[3..] {
        if token.len() < 20 {
            // Padding groups come before the keys.
            if keys > 0 {
                return false;
            }
            continue;
        }
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token) {
            Ok(bytes) if bytes.len() == 32 || bytes.len() == 1184 => keys += 1,
            _ => return false,
        }
    }
    keys > 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Flow {
    #[default]
    None,
    /// `xtls-rprx-vision` — splices inner TLS records to defeat TLS-in-TLS
    /// detection.
    Vision,
    /// `xtls-rprx-vision-udp443`.
    VisionUdp443,
}

impl Flow {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "" | "none" => Flow::None,
            "xtls-rprx-vision" => Flow::Vision,
            "xtls-rprx-vision-udp443" => Flow::VisionUdp443,
            _ => return None,
        })
    }

    pub fn is_vision(self) -> bool {
        matches!(self, Flow::Vision | Flow::VisionUdp443)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Flow::None => "",
            Flow::Vision => "xtls-rprx-vision",
            Flow::VisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanConfig {
    pub address: Address,
    pub port: u16,
    /// SHA-224 of the password, hex-encoded — the value sent on the wire.
    pub password_hash: [u8; 56],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3Chacha20Poly1305,
}

impl ShadowsocksMethod {
    /// A SIP022 ("Shadowsocks 2022") method rather than a legacy AEAD one.
    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm | Self::Blake3Chacha20Poly1305
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Self::Chacha20Poly1305,
            "2022-blake3-aes-128-gcm" => Self::Blake3Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Blake3Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Blake3Chacha20Poly1305,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksConfig {
    pub address: Address,
    pub port: u16,
    pub method: ShadowsocksMethod,
    pub password: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl VmessCipher {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Self::Auto,
            "aes-128-gcm" => Self::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha20Poly1305,
            "none" => Self::None,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessConfig {
    pub address: Address,
    pub port: u16,
    pub uuid: [u8; 16],
    pub cipher: VmessCipher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsConfig {
    pub address: Address,
    pub port: u16,
    pub password: Box<str>,
}

/// A SOCKS5 upstream (RFC 1928). The credential is RFC 1929 user/password; a
/// local Tor or Psiphon client needs none, a remote SOCKS5 server often does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksConfig {
    pub address: Address,
    pub port: u16,
    pub auth: Option<SocksCredential>,
    /// The upstream is an HTTP proxy spoken to with `CONNECT` (Xray's `http`
    /// outbound), not a SOCKS5 one. Everything else about it is the same: a
    /// TCP-only upstream that resolves names itself.
    pub http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksCredential {
    pub username: Box<str>,
    pub password: Box<str>,
}

/// How the embedded Tor client reaches the Tor network.
///
/// All fields are optional: an empty config connects to Tor directly, which
/// works wherever Tor is not blocked. Where it is (Iran, Russia, China) bridges
/// are needed, and most bridge types need a pluggable-transport program that
/// is not part of this build, so it is named in `transports`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TorConfig {
    /// Bridge lines as the Tor Project hands them out, with or without the
    /// leading `Bridge `, e.g. `obfs4 192.0.2.5:443 FINGERPRINT cert=… iat-mode=0`.
    pub bridges: Vec<Box<str>>,
    /// Pluggable-transport programs, as (transport name, program path):
    /// `("obfs4", "/usr/bin/lyrebird")`, `("snowflake", "…/snowflake-client")`.
    pub transports: Vec<(Box<str>, Box<str>)>,
    /// Where Tor keeps its directory cache and state. `None` picks a per-user
    /// folder. A warm cache is what makes the second start fast.
    pub data_dir: Option<Box<str>>,
    /// Soft memory ceiling in MiB for the Tor client. `0` means the default.
    pub memory_mib: u32,
}

/// How a MasterDnsVPN server picks the destination of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MasterDnsMode {
    /// The stream names its destination and the server dials it
    /// (`PROTOCOL_TYPE = "SOCKS5"`, what the installer sets up).
    #[default]
    Socks5,
    /// The server forwards every stream to one fixed place.
    Tcp,
}

/// How to reach one MasterDnsVPN server. See [`OutboundProtocol::MasterDns`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MasterDnsConfig {
    /// The tunnel domain, delegated to the server (`t.example.com`).
    pub domain: Box<str>,
    /// The shared key. A secret: it is never printed.
    pub key: Box<str>,
    /// The encryption method id (5 = AES-256-GCM).
    pub method: u8,
    /// Resolvers the queries go through; the server's own address works too
    /// when it answers on UDP 53.
    pub resolvers: Vec<SocketAddr>,
    pub mode: MasterDnsMode,
}

impl std::fmt::Debug for MasterDnsConfig {
    // The key never prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterDnsConfig")
            .field("domain", &self.domain)
            .field("method", &self.method)
            .field("resolvers", &self.resolvers)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Lowest memory ceiling the Tor client is given. Below this Arti refuses
/// circuits it cannot hold, which looks like a dead network.
pub const TOR_MIN_MEMORY_MIB: u32 = 32;

/// A Tide server to connect to. The keys are the raw bytes; links and JSON
/// write them as unpadded URL-safe base64.
#[derive(Clone, PartialEq, Eq)]
pub struct TideConfig {
    pub address: Address,
    pub port: u16,
    /// The path prefix the server answers Tide requests under.
    pub path: Box<str>,
    /// The server's public key, which the handshake is made against.
    pub server_key: [u8; 32],
    /// This user's id on that server.
    pub user: [u8; 16],
    /// Uploads on a connection of their own, apart from downloads.
    pub split: bool,
    /// End each upload request as soon as nothing is waiting, for a server
    /// behind a proxy that collects a whole request before passing it on.
    pub packet_upload: bool,
    /// Carry UDP too, over the session's datagram lane. Off for a server
    /// built before the lane existed, which would refuse the request for it.
    pub datagrams: bool,
    /// Replace a working connection now and then, before it gets old enough
    /// to be remembered. On unless the link says `rotate=0`.
    pub rotate: bool,
    /// Everything else a link can adjust; all unset in a plain link.
    pub tuning: TideTuning,
}

/// The optional knobs of a Tide link, each `None` (or empty) meaning "the
/// built-in default". They change how the client *looks* and *paces*; none of
/// them changes what the server must know, so any client may use any mix
/// against the same server.
///
/// How it is read: [`TideTuning::parse`] takes a lookup (`key -> text`), so a
/// share link's query and a JSON `settings` object go through the same
/// checks. A value that is out of range is an error, never silently clamped:
/// `pipes=9` should say so, not quietly mean 4.
///
/// | key         | meaning                                               | range            |
/// |-------------|-------------------------------------------------------|------------------|
/// | `authority` | HTTP `:authority` / `Host`, apart from the TLS name   | a host name      |
/// | `ua`        | browser: `chrome` `firefox` `safari` `edge` `android` `ios`, or any text | printable ASCII |
/// | `lang`      | `accept-language`                                     | printable ASCII  |
/// | `headers`   | extra headers, `name:value,name:value`                | up to 8          |
/// | `pipes`     | download requests open at once                        | 1 to 4           |
/// | `uploads`   | upload requests waiting for an answer at once         | 1 to 6           |
/// | `ping`      | seconds between HTTP/2 pings                          | 4 to 120         |
/// | `idle`      | seconds with no stream before a session closes        | 30 to 3600       |
/// | `linger`    | milliseconds an upload waits for more to send         | 0 to 5000        |
/// | `age`       | connection age before replacing it, `min-max` seconds | 30 to 86400      |
/// | `volume`    | megabytes through a connection before replacing it    | 64 to 65536      |
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TideTuning {
    pub authority: Option<Box<str>>,
    pub user_agent: Option<Box<str>>,
    pub language: Option<Box<str>>,
    pub headers: Vec<(Box<str>, Box<str>)>,
    pub down_pipes: Option<u8>,
    pub up_pipes: Option<u8>,
    pub ping_secs: Option<u16>,
    pub idle_secs: Option<u16>,
    pub linger_ms: Option<u16>,
    pub age_secs: Option<(u32, u32)>,
    pub volume_mb: Option<u32>,
}

/// The `User-Agent` a `ua=` preset stands for. Each is a current stable
/// release of that browser, so the header matches what the TLS `fp=` of the
/// same name sends.
pub fn tide_user_agent_preset(name: &str) -> Option<&'static str> {
    Some(match name {
        "chrome" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "edge" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
        "firefox" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
        "safari" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
        "android" => "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        "ios" => "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
        _ => return None,
    })
}

/// Header names a link may not set: the ones Tide or HTTP/2 itself depends on
/// (`content-type` marks a Tide body, `content-length` frames it), the ones
/// that would change how the connection behaves, and the two that have their
/// own keys.
const TIDE_HEADERS_REFUSED: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "proxy-authorization",
    "proxy-connection",
    "user-agent",
    "accept-language",
];

fn tide_plain_text(text: &str, what: &str, max: usize) -> Result<Box<str>, String> {
    let text = text.trim();
    if text.is_empty() || text.len() > max || !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(format!(
            "Tide {what} must be 1 to {max} printable ASCII characters"
        ));
    }
    Ok(text.into())
}

fn tide_number<T: TryFrom<u64>>(text: &str, what: &str, low: u64, high: u64) -> Result<T, String> {
    text.trim()
        .parse::<u64>()
        .ok()
        .filter(|n| (low..=high).contains(n))
        .and_then(|n| T::try_from(n).ok())
        .ok_or_else(|| format!("Tide {what} must be a number from {low} to {high}"))
}

impl TideTuning {
    /// Read the options from `get`, which returns the text for a key or
    /// `None` when the link does not set it. An empty value counts as unset.
    pub fn parse(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |key: &str| get(key).filter(|value| !value.trim().is_empty());
        let mut tuning = Self::default();
        if let Some(name) = get("authority").or_else(|| get("host")) {
            let name = name.trim();
            let plain = name.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
            });
            if name.len() > 253 || !plain {
                return Err("Tide authority must be a host name".into());
            }
            tuning.authority = Some(name.to_ascii_lowercase().into());
        }
        if let Some(agent) = get("ua") {
            let key = agent.trim().to_ascii_lowercase();
            tuning.user_agent = Some(match tide_user_agent_preset(&key) {
                Some(preset) => preset.into(),
                None => tide_plain_text(&agent, "ua", 256)?,
            });
        }
        if let Some(language) = get("lang") {
            tuning.language = Some(tide_plain_text(&language, "lang", 64)?);
        }
        if let Some(list) = get("headers") {
            for pair in list.split(',').filter(|pair| !pair.trim().is_empty()) {
                let (name, value) = pair
                    .split_once(':')
                    .ok_or("Tide headers must look like name:value,name:value")?;
                let name = name.trim().to_ascii_lowercase();
                let token = !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                if !token || TIDE_HEADERS_REFUSED.contains(&name.as_str()) {
                    return Err(format!("Tide headers may not set {name:?}"));
                }
                let value = tide_plain_text(value, "header value", 512)?;
                tuning.headers.push((name.into(), value));
            }
            if tuning.headers.len() > 8 {
                return Err("Tide headers allows at most 8 headers".into());
            }
        }
        if let Some(text) = get("pipes") {
            tuning.down_pipes = Some(tide_number(&text, "pipes", 1, 4)?);
        }
        if let Some(text) = get("uploads") {
            tuning.up_pipes = Some(tide_number(&text, "uploads", 1, 6)?);
        }
        if let Some(text) = get("ping") {
            tuning.ping_secs = Some(tide_number(&text, "ping", 4, 120)?);
        }
        if let Some(text) = get("idle") {
            tuning.idle_secs = Some(tide_number(&text, "idle", 30, 3600)?);
        }
        if let Some(text) = get("linger") {
            tuning.linger_ms = Some(tide_number(&text, "linger", 0, 5000)?);
        }
        if let Some(text) = get("age") {
            let (low, high) = text.split_once('-').unwrap_or((&text, &text));
            let low: u32 = tide_number(low, "age", 30, 86_400)?;
            let high: u32 = tide_number(high, "age", 30, 86_400)?;
            if low > high {
                return Err("Tide age must be min-max, smallest first".into());
            }
            tuning.age_secs = Some((low, high));
        }
        if let Some(text) = get("volume") {
            tuning.volume_mb = Some(tide_number(&text, "volume", 64, 65_536)?);
        }
        Ok(tuning)
    }
}

// Header values may carry a cookie, which is a password of sorts: the debug
// form names the headers and stands a digest in for their values, so two
// different cookies still make two different cache keys.
impl std::fmt::Debug for TideTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digest = self
            .headers
            .iter()
            .flat_map(|(_, value)| value.bytes())
            .fold(0u64, |mark, b| {
                mark.wrapping_mul(0x100_0000_01b3) ^ u64::from(b)
            });
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| &**name).collect();
        f.debug_struct("TideTuning")
            .field("authority", &self.authority)
            .field("user_agent", &self.user_agent)
            .field("language", &self.language)
            .field("headers", &names)
            .field("headers_digest", &format_args!("{digest:016x}"))
            .field("down_pipes", &self.down_pipes)
            .field("up_pipes", &self.up_pipes)
            .field("ping_secs", &self.ping_secs)
            .field("idle_secs", &self.idle_secs)
            .field("linger_ms", &self.linger_ms)
            .field("age_secs", &self.age_secs)
            .field("volume_mb", &self.volume_mb)
            .finish()
    }
}

/// How much a Tide server pads its answers to an upload, so the flow's
/// up/down ratio looks like browsing. Costs at most the fraction of the
/// upload named by the level; nothing when nothing is uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TideShape {
    Off,
    #[default]
    Light,
    Full,
}

impl TideShape {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "off" => Some(Self::Off),
            "light" => Some(Self::Light),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Config {
    pub address: Address,
    pub port: u16,
    pub password: Box<str>,
    /// The Salamander obfuscation password (`obfs=salamander`), the only
    /// obfuscation Hysteria 2 defines. Every UDP datagram is wrapped in it;
    /// the server must be set up with the same one.
    pub obfs_password: Option<Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicConfig {
    pub address: Address,
    pub port: u16,
    pub uuid: [u8; 16],
    pub password: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JuicityConfig {
    pub address: Address,
    pub port: u16,
    pub uuid: [u8; 16],
    pub password: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaHeaderRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziaWireguardConfig {
    pub address: Address,
    pub port: u16,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub tunnel_address: IpAddr,
    pub persistent_keepalive: Option<u16>,
    pub junk_count: u16,
    pub junk_min: u16,
    pub junk_max: u16,
    pub s1: u16,
    pub s2: u16,
    pub s3: u16,
    pub s4: u16,
    pub h1: AmneziaHeaderRange,
    pub h2: AmneziaHeaderRange,
    pub h3: AmneziaHeaderRange,
    pub h4: AmneziaHeaderRange,
    /// The three reserved bytes of every WireGuard message; Cloudflare WARP
    /// uses them as a client id (its `client_id`). Zero otherwise.
    pub reserved: [u8; 3],
    /// Whether the key pair above is real. A MASQUE-only WARP account has no
    /// WireGuard half and keeps zeroed keys here.
    pub has_wireguard: bool,
    /// Which way this outbound reaches Cloudflare. Only WARP has more than
    /// one; an ordinary WireGuard server is always [`WarpRoute::WireGuard`].
    pub route: WarpRoute,
    /// The account's MASQUE side, when it has one.
    pub masque: Option<Box<MasqueConfig>>,
    /// Share links of servers to take part in the connection, in whichever
    /// order [`Self::hybrid`] asks for.
    pub exits: Vec<Arc<str>>,
    /// Which order the tunnel and the servers are brought up in.
    pub hybrid: HybridMode,
    /// Within [`HybridMode::WarpFirst`]: an exit carries traffic first, with
    /// the tunnel alone as the failsafe, instead of the other way round.
    /// Always false for [`HybridMode::ServerFirst`].
    pub prefer_exit: bool,
    /// WARP inside WARP: a second account's WireGuard session carried inside
    /// this account's MASQUE tunnel. Cloudflare then sees that session arrive
    /// from its own network abroad and gives it an exit address located
    /// there, where the MASQUE tunnel alone is given one located where the
    /// user is. Only the MASQUE routes use it; the account must have WARP
    /// switched on, or its WireGuard session carries nothing.
    pub inner: Option<Box<AmneziaWireguardConfig>>,
}

/// The order a WARP outbound brings its tunnel and its servers up in.
///
/// [`Self::ServerFirst`] (the UI's "hybrid") dials a listed server and reaches
/// Cloudflare's edge *through* it, so the local network sees an ordinary
/// connection to that server and never sees Cloudflare; only MASQUE over
/// HTTP/2 can ride a server that way, and the servers must be reachable from
/// here. [`Self::WarpFirst`] (the UI's "reverse hybrid") dials the tunnel
/// directly over any route and reaches a listed server from inside it, which
/// also reaches servers the local network blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HybridMode {
    /// A server first, then Cloudflare's tunnel through it.
    ServerFirst,
    /// Cloudflare's tunnel first, then a server from inside it.
    #[default]
    WarpFirst,
}

impl HybridMode {
    /// The `mode` spelling in a `warp` outbound's settings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServerFirst => "server-first",
            Self::WarpFirst => "warp-first",
        }
    }
}

impl AmneziaWireguardConfig {
    /// Whether this outbound has a WireGuard half at all.
    pub fn wireguard_usable(&self) -> bool {
        self.has_wireguard
    }
}

/// How a WARP outbound reaches Cloudflare.
///
/// On some networks QUIC to foreign hosts is dropped, plain
/// WireGuard is filtered unless junk packets precede the handshake, and
/// HTTP/2 to a Cloudflare edge address under a harmless SNI gets through; on
/// other networks any of them can be the fast one. `Auto` races them and keeps
/// the first that carries traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WarpRoute {
    #[default]
    Auto,
    WireGuard,
    MasqueHttp2,
    MasqueHttp3,
}

impl WarpRoute {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "hybrid" => Self::Auto,
            "wireguard" | "wg" => Self::WireGuard,
            "masque-h2" | "masque-http2" | "h2" | "http2" => Self::MasqueHttp2,
            "masque-h3" | "masque-http3" | "h3" | "http3" => Self::MasqueHttp3,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::WireGuard => "wireguard",
            Self::MasqueHttp2 => "masque-h2",
            Self::MasqueHttp3 => "masque-h3",
        }
    }

    pub fn uses_masque(self) -> bool {
        !matches!(self, Self::WireGuard)
    }
}

/// The MASQUE half of a WARP account (see `zero_transport::masque`).
#[derive(Clone, PartialEq, Eq)]
pub struct MasqueConfig {
    /// The enrolled ECDSA P-256 private key, DER, PKCS#8 or SEC1.
    pub private_key: Vec<u8>,
    /// The Cloudflare endpoint key to pin: a DER `SubjectPublicKeyInfo`.
    pub server_public_key: Vec<u8>,
    /// The tunnel's own addresses, one per family (WARP hands out both).
    pub addresses: Vec<IpAddr>,
    /// Edge addresses for the HTTP/2 (TCP) and HTTP/3 (UDP) tunnels.
    pub http2_endpoints: Vec<std::net::SocketAddr>,
    pub http3_endpoints: Vec<std::net::SocketAddr>,
    /// The TLS server name each transport sends.
    pub http2_sni: Arc<str>,
    pub http3_sni: Arc<str>,
    /// The `:authority` of the CONNECT request.
    pub authority: Arc<str>,
}

impl std::fmt::Debug for MasqueConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never reaches a log.
        f.debug_struct("MasqueConfig")
            .field("addresses", &self.addresses)
            .field("http2_endpoints", &self.http2_endpoints)
            .field("http3_endpoints", &self.http3_endpoints)
            .field("http2_sni", &self.http2_sni)
            .field("http3_sni", &self.http3_sni)
            .finish_non_exhaustive()
    }
}

impl MasqueConfig {
    /// Edge addresses to try for the HTTP/2 tunnel, in order. The address the
    /// official client uses (`.2`) is last: it is the one most often filtered.
    pub const DEFAULT_HTTP2_ENDPOINTS: [&'static str; 4] = [
        "162.159.198.4:443",
        "162.159.198.7:443",
        "162.159.198.100:443",
        "162.159.198.2:443",
    ];
    /// The address the official client's QUIC tunnel uses.
    pub const DEFAULT_HTTP3_ENDPOINTS: [&'static str; 1] = ["162.159.198.1:443"];
    /// A name the filters there let through; Cloudflare's edge answers
    /// whatever name it is given, and the server is verified by its key.
    pub const DEFAULT_HTTP2_SNI: &'static str = "www.speedtest.net";
    /// The name the official client sends.
    pub const DEFAULT_HTTP3_SNI: &'static str = "consumer-masque.cloudflareclient.com";
    pub const DEFAULT_AUTHORITY: &'static str = "cloudflareaccess.com";

    pub fn default_endpoints(list: &[&str]) -> Vec<std::net::SocketAddr> {
        list.iter().filter_map(|text| text.parse().ok()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Outbound {
    pub tag: Arc<str>,
    pub protocol: OutboundProtocol,
    pub stream: StreamSettings,
    /// Xray's VLESS Mux switch and bounded carrier concurrency.
    pub mux: MuxConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MuxConfig {
    pub enabled: bool,
    pub max_concurrency: u16,
    /// Xray's `xudpProxyUDP443`: what happens to UDP datagrams for port 443
    /// (QUIC) on a mux outbound.
    pub udp443: Udp443,
}

/// Xray's `xudpProxyUDP443`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Udp443 {
    /// Refused, so the application falls back to TCP (Xray's default).
    #[default]
    Reject,
    /// Carried over the mux like any other datagram.
    Allow,
    /// Sent outside the mux, as the outbound would without it.
    Skip,
}

impl Outbound {
    /// Whether this outbound can run over a connection another outbound
    /// already opened (`dialerProxy`, a WARP exit): a stream protocol over
    /// plain TCP, WebSocket, HTTPUpgrade or gRPC, without Mux. QUIC carriers
    /// and XHTTP need a socket of their own. A Tide server is not listed: it
    /// needs several connections, so it takes a way to open them instead
    /// (`zero_runtime::outbound::connect_tide_via`) and has no place where a
    /// single carried stream is all there is (a WARP exit list).
    pub fn chainable(&self) -> bool {
        matches!(
            self.protocol,
            OutboundProtocol::Vless(_)
                | OutboundProtocol::Vmess(_)
                | OutboundProtocol::Trojan(_)
                | OutboundProtocol::Shadowsocks(_)
                | OutboundProtocol::AnyTls(_)
                | OutboundProtocol::Socks(_)
        ) && !self.mux.enabled
            && matches!(
                self.stream.transport,
                Transport::Raw
                    | Transport::WebSocket(_)
                    | Transport::HttpUpgrade(_)
                    | Transport::Grpc(_)
            )
    }

    /// Reject combinations that cannot work, before any socket is opened.
    pub fn validate(&self) -> Result<(), String> {
        let caps = self.stream.transport.capabilities();

        // Salamander, port hopping and QUIC parameters shape a QUIC carrier's
        // UDP socket. On anything else they would be dropped without a word,
        // and the connection would go out plain while the config said it was
        // obfuscated.
        let evasion = &self.stream.evasion;
        if (evasion.udp_salamander.is_some() || evasion.udp_hop.is_some() || evasion.quic.is_some())
            && !matches!(self.protocol, OutboundProtocol::Hysteria2(_))
        {
            return Err(format!(
                "outbound {}: the UDP masks salamander and udphop and quicParams apply to Hysteria 2 only",
                self.tag
            ));
        }

        if self.stream.raw_http_header.is_some() && !matches!(self.stream.transport, Transport::Raw)
        {
            return Err(format!(
                "outbound {}: raw HTTP camouflage requires the raw carrier",
                self.tag
            ));
        }

        if matches!(
            &self.stream.security,
            Security::Tls(TlsConfig { ech: Some(_), .. })
        ) && self.stream.evasion.tcp_fragment.is_some()
        {
            return Err(format!(
                "outbound {}: ECH cannot be combined with ClientHello fragmentation",
                self.tag
            ));
        }

        // A direct outbound has no TLS of its own, but it carries the TLS of
        // whatever is behind the proxy, and that hello can take a decoy.
        if self.stream.evasion.sni_desync.is_some()
            && matches!(self.stream.security, Security::None)
            && !matches!(self.protocol, OutboundProtocol::Freedom { .. })
        {
            return Err(format!(
                "outbound {}: SNI desync requires a TLS or REALITY carrier",
                self.tag
            ));
        }
        if self.stream.evasion.sni_desync.is_some()
            && matches!(
                &self.stream.security,
                Security::Tls(TlsConfig { ech: Some(_), .. })
            )
        {
            return Err(format!(
                "outbound {}: SNI desync cannot be combined with ECH",
                self.tag
            ));
        }

        if matches!(self.stream.security, Security::Reality(_)) && !caps.supports_reality {
            return Err(format!(
                "outbound {}: REALITY is not supported over {} transport",
                self.tag,
                self.stream.transport.name()
            ));
        }

        if let OutboundProtocol::Vless(v) = &self.protocol {
            // VLESS Encryption gives Vision its own record layer to switch
            // on, so Xray allows the pair over any transport and security.
            if v.flow.is_vision() && !v.encrypted() {
                if !caps.supports_vision {
                    return Err(format!(
                        "outbound {}: flow {} runs over raw TCP only, not {} \
                         (Xray allows other transports only with VLESS Encryption)",
                        self.tag,
                        v.flow.as_str(),
                        self.stream.transport.name()
                    ));
                }
                if matches!(self.stream.security, Security::None) {
                    return Err(format!(
                        "outbound {}: flow {} requires TLS or REALITY \
                         (or VLESS Encryption)",
                        self.tag,
                        v.flow.as_str()
                    ));
                }
            }
            if v.encrypted() && !is_vless_encryption(&v.encryption) {
                return Err(format!(
                    "outbound {}: VLESS encryption must be \"none\" or a valid \
                     mlkem768x25519plus setting, got {:?}",
                    self.tag, v.encryption
                ));
            }
            if self.mux.enabled {
                if v.flow.is_vision() {
                    return Err(format!(
                        "outbound {}: VLESS Mux cannot be combined with Vision",
                        self.tag
                    ));
                }
                if matches!(
                    self.stream.transport,
                    Transport::Xhttp(WebSocketConfig {
                        xhttp_http_version: XhttpHttpVersion::Http3,
                        ..
                    })
                ) {
                    return Err(format!(
                        "outbound {}: VLESS Mux is not supported over XHTTP HTTP/3",
                        self.tag
                    ));
                }
            }
        } else if self.mux.enabled {
            return Err(format!(
                "outbound {}: Mux is only supported for VLESS",
                self.tag
            ));
        }

        if let OutboundProtocol::Shadowsocks(s) = &self.protocol {
            if s.password.is_empty() {
                return Err(format!(
                    "outbound {}: Shadowsocks password must not be empty",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: Shadowsocks currently requires the raw carrier",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::MasterDns(m) = &self.protocol {
            let domain = m.domain.trim();
            if domain.is_empty()
                || domain.len() > 200
                || domain.starts_with('.')
                || !domain.contains('.')
                || !domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Err(format!(
                    "outbound {}: the MasterDNS domain must be a name like t.example.com",
                    self.tag
                ));
            }
            if m.key.is_empty() {
                return Err(format!("outbound {}: the MasterDNS key is empty", self.tag));
            }
            // Method 2 (ChaCha20) is deliberately not offered: upstream runs it
            // without authentication.
            if !matches!(m.method, 0 | 1 | 3..=5) {
                return Err(format!(
                    "outbound {}: MasterDNS encryption method {} is not supported",
                    self.tag, m.method
                ));
            }
            if m.resolvers.is_empty() {
                return Err(format!(
                    "outbound {}: MasterDNS needs at least one resolver",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::Tor(tor) = &self.protocol {
            if tor.memory_mib != 0 && tor.memory_mib < TOR_MIN_MEMORY_MIB {
                return Err(format!(
                    "outbound {}: Tor needs at least {TOR_MIN_MEMORY_MIB} MiB of memory",
                    self.tag
                ));
            }
            if tor
                .bridges
                .iter()
                .any(|b| b.trim().is_empty() || b.len() > 2048)
            {
                return Err(format!(
                    "outbound {}: a Tor bridge line is empty or too long",
                    self.tag
                ));
            }
            if tor
                .transports
                .iter()
                .any(|(name, path)| name.trim().is_empty() || path.trim().is_empty())
            {
                return Err(format!(
                    "outbound {}: a Tor transport needs a name and a program path",
                    self.tag
                ));
            }
            // A bridge that names a transport nobody can run would only fail
            // minutes later, inside Tor, with a message about circuits.
            for line in &tor.bridges {
                let line = line.trim();
                let line = line.strip_prefix("Bridge ").map_or(line, str::trim);
                let first = line.split_whitespace().next().unwrap_or("");
                let is_transport = !first.contains(':') && !first.is_empty();
                if is_transport
                    && !tor
                        .transports
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case(first))
                {
                    return Err(format!(
                        "outbound {}: bridge uses the {first:?} transport but no program is set for it",
                        self.tag
                    ));
                }
            }
        }

        if let OutboundProtocol::Socks(socks) = &self.protocol {
            if socks.port == 0 {
                return Err(format!("outbound {}: SOCKS5 port must not be 0", self.tag));
            }
            if let Some(auth) = &socks.auth {
                if auth.username.len() > 255 || auth.password.len() > 255 {
                    return Err(format!(
                        "outbound {}: SOCKS5 user name and password are at most 255 bytes",
                        self.tag
                    ));
                }
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: SOCKS5 requires the raw carrier",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::AnyTls(anytls) = &self.protocol {
            if anytls.password.is_empty() {
                return Err(format!(
                    "outbound {}: AnyTLS password must not be empty",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: AnyTLS currently requires the raw carrier",
                    self.tag
                ));
            }
            if !matches!(self.stream.security, Security::Tls(_)) {
                return Err(format!(
                    "outbound {}: AnyTLS requires ordinary certificate TLS",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::Hysteria2(hysteria) = &self.protocol {
            if hysteria.password.is_empty() {
                return Err(format!(
                    "outbound {}: Hysteria2 password must not be empty",
                    self.tag
                ));
            }
            if !matches!(self.stream.security, Security::Tls(_)) {
                return Err(format!(
                    "outbound {}: Hysteria2 requires ordinary certificate TLS",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: Hysteria2 currently requires the raw QUIC carrier",
                    self.tag
                ));
            }
            if self.stream.evasion.has_non_quic_shaping() || self.stream.raw_http_header.is_some() {
                return Err(format!(
                    "outbound {}: Hysteria2 cannot carry TCP finalmask or raw HTTP camouflage",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::Tuic(tuic) = &self.protocol {
            if tuic.password.is_empty() {
                return Err(format!(
                    "outbound {}: TUIC password must not be empty",
                    self.tag
                ));
            }
            if !matches!(self.stream.security, Security::Tls(_)) {
                return Err(format!(
                    "outbound {}: TUIC requires ordinary certificate TLS",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: TUIC uses its own QUIC carrier",
                    self.tag
                ));
            }
            if self.stream.evasion.has_non_quic_shaping() || self.stream.raw_http_header.is_some() {
                return Err(format!(
                    "outbound {}: TUIC cannot carry TCP finalmask or raw HTTP camouflage",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::Juicity(juicity) = &self.protocol {
            if juicity.password.is_empty() {
                return Err(format!(
                    "outbound {}: Juicity password must not be empty",
                    self.tag
                ));
            }
            if !matches!(self.stream.security, Security::Tls(_)) {
                return Err(format!(
                    "outbound {}: Juicity requires ordinary certificate TLS",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: Juicity uses its own QUIC carrier",
                    self.tag
                ));
            }
            if self.stream.evasion.has_non_quic_shaping() || self.stream.raw_http_header.is_some() {
                return Err(format!(
                    "outbound {}: Juicity cannot carry TCP finalmask or raw HTTP camouflage",
                    self.tag
                ));
            }
        }

        if let Security::ShadowTls(shadowtls) = &self.stream.security {
            if shadowtls.password.is_empty() {
                return Err(format!(
                    "outbound {}: ShadowTLS password must not be empty",
                    self.tag
                ));
            }
            if shadowtls.server_name.is_empty() {
                return Err(format!(
                    "outbound {}: ShadowTLS needs a decoy serverName",
                    self.tag
                ));
            }
            if !matches!(self.protocol, OutboundProtocol::Shadowsocks(_)) {
                return Err(format!(
                    "outbound {}: ShadowTLS carries Shadowsocks only",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw) {
                return Err(format!(
                    "outbound {}: ShadowTLS runs over the raw carrier only",
                    self.tag
                ));
            }
            // Splitting the ClientHello would break the relay's frame
            // extraction and the data-stream HMAC, so no TCP evasion or raw
            // HTTP camouflage underneath it.
            if !self.stream.evasion.is_empty() || self.stream.raw_http_header.is_some() {
                return Err(format!(
                    "outbound {}: ShadowTLS cannot carry TCP finalmask or raw HTTP camouflage",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::AmneziaWireguard(wireguard) = &self.protocol {
            match (wireguard.route, &wireguard.masque) {
                (WarpRoute::WireGuard, _) if !wireguard.wireguard_usable() => {
                    return Err(format!(
                        "outbound {}: the WireGuard route needs a WireGuard key pair",
                        self.tag
                    ));
                }
                (WarpRoute::Auto, None) if !wireguard.wireguard_usable() => {
                    return Err(format!(
                        "outbound {}: a WARP outbound needs WireGuard keys or a MASQUE key",
                        self.tag
                    ));
                }
                (route, None) if route.uses_masque() && route != WarpRoute::Auto => {
                    return Err(format!(
                        "outbound {}: the {} route needs a MASQUE key",
                        self.tag,
                        route.name()
                    ));
                }
                _ => {}
            }
            if let Some(masque) = &wireguard.masque {
                let wants = |route: WarpRoute| {
                    matches!(wireguard.route, WarpRoute::Auto) || wireguard.route == route
                };
                if masque.private_key.is_empty() || masque.server_public_key.is_empty() {
                    return Err(format!(
                        "outbound {}: MASQUE needs its private key and the server key to pin",
                        self.tag
                    ));
                }
                if masque.addresses.is_empty() {
                    return Err(format!(
                        "outbound {}: MASQUE needs the tunnel address of the account",
                        self.tag
                    ));
                }
                if (wants(WarpRoute::MasqueHttp2) && masque.http2_endpoints.is_empty())
                    || (wants(WarpRoute::MasqueHttp3) && masque.http3_endpoints.is_empty())
                {
                    return Err(format!(
                        "outbound {}: MASQUE has no endpoint for the chosen transport",
                        self.tag
                    ));
                }
            }
            if wireguard.port == 0 {
                return Err(format!(
                    "outbound {}: AmneziaWG endpoint port must be non-zero",
                    self.tag
                ));
            }
            if wireguard.junk_count > 64
                || wireguard.junk_min > wireguard.junk_max
                || wireguard.junk_max > 4096
            {
                return Err(format!(
                    "outbound {}: AmneziaWG junk bounds are invalid",
                    self.tag
                ));
            }
            if [wireguard.s1, wireguard.s2, wireguard.s3, wireguard.s4]
                .into_iter()
                .any(|padding| padding > 4096)
            {
                return Err(format!(
                    "outbound {}: AmneziaWG padding exceeds 4096 bytes",
                    self.tag
                ));
            }
            let headers = [wireguard.h1, wireguard.h2, wireguard.h3, wireguard.h4];
            if headers.iter().any(|range| range.min > range.max)
                || headers.iter().enumerate().any(|(index, left)| {
                    headers
                        .iter()
                        .skip(index + 1)
                        .any(|right| left.min <= right.max && right.min <= left.max)
                })
            {
                return Err(format!(
                    "outbound {}: AmneziaWG header ranges overlap or are inverted",
                    self.tag
                ));
            }
            if !matches!(self.stream.transport, Transport::Raw)
                || !matches!(self.stream.security, Security::None)
            {
                return Err(format!(
                    "outbound {}: AmneziaWG uses its own unauthenticated UDP carrier",
                    self.tag
                ));
            }
        }

        if let Security::Reality(r) = &self.stream.security {
            if !r.fingerprint.supports_reality() {
                return Err(format!(
                    "outbound {}: fingerprint {:?} has no X25519 key share and cannot be used with REALITY",
                    self.tag, r.fingerprint
                ));
            }
            if r.short_id.len() > 8 {
                return Err(format!(
                    "outbound {}: REALITY shortId must be at most 8 bytes",
                    self.tag
                ));
            }
        }

        if let Transport::Xhttp(settings) = &self.stream.transport {
            if settings.xhttp_http_version == XhttpHttpVersion::Http3
                && !matches!(self.stream.security, Security::Tls(_))
            {
                return Err(format!(
                    "outbound {}: XHTTP HTTP/3 requires ordinary certificate TLS",
                    self.tag
                ));
            }
            if settings.xhttp_http_version == XhttpHttpVersion::Http3
                && !matches!(
                    settings.xhttp_mode,
                    XhttpMode::StreamOne | XhttpMode::StreamUp | XhttpMode::PacketUp
                )
            {
                return Err(format!(
                    "outbound {}: XHTTP HTTP/3 supports stream-one, stream-up, or packet-up",
                    self.tag
                ));
            }
        }

        Ok(())
    }

    /// Dial port `port` instead of the one this outbound names. Only the
    /// TCP protocols have a port to move; others are left and `false` says so.
    pub fn set_port(&mut self, port: u16) -> bool {
        match &mut self.protocol {
            OutboundProtocol::Vless(v) => v.port = port,
            OutboundProtocol::Trojan(t) => t.port = port,
            OutboundProtocol::Shadowsocks(s) => s.port = port,
            OutboundProtocol::Vmess(v) => v.port = port,
            OutboundProtocol::AnyTls(a) => a.port = port,
            _ => return false,
        }
        true
    }

    /// The remote endpoint this outbound dials, if any.
    pub fn endpoint(&self) -> Option<(Address, u16)> {
        match &self.protocol {
            OutboundProtocol::Vless(v) => Some((v.address.clone(), v.port)),
            OutboundProtocol::Trojan(t) => Some((t.address.clone(), t.port)),
            OutboundProtocol::Shadowsocks(s) => Some((s.address.clone(), s.port)),
            OutboundProtocol::Vmess(v) => Some((v.address.clone(), v.port)),
            OutboundProtocol::AnyTls(a) => Some((a.address.clone(), a.port)),
            OutboundProtocol::Socks(k) => Some((k.address.clone(), k.port)),
            OutboundProtocol::Tide(t) => Some((t.address.clone(), t.port)),
            OutboundProtocol::Hysteria2(h) => Some((h.address.clone(), h.port)),
            OutboundProtocol::Tuic(t) => Some((t.address.clone(), t.port)),
            OutboundProtocol::Juicity(j) => Some((j.address.clone(), j.port)),
            OutboundProtocol::AmneziaWireguard(w) => Some((w.address.clone(), w.port)),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------- inbounds

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundProtocol {
    Socks,
    Http,
    /// SOCKS5 and HTTP auto-detected on one port.
    Mixed,
    /// Raw VLESS server inbound. TLS/REALITY termination is selected by the
    /// listener's stream configuration in a later server-capable generation;
    /// this first-class protocol still makes the wire/auth boundary explicit.
    Vless(VlessInboundConfig),
    /// Trojan password-authenticated server inbound.
    Trojan(TrojanInboundConfig),
    /// Modern AEAD VMess server inbound.
    Vmess(VmessInboundConfig),
    /// Legacy AEAD Shadowsocks server inbound.
    Shadowsocks(ShadowsocksInboundConfig),
    /// AnyTLS v2 over ordinary certificate TLS.
    AnyTls(AnyTlsInboundConfig),
    /// Tide server: HTTP/2, with certificate TLS here or in a proxy in front.
    Tide(TideInboundConfig),
    /// Tide relay: shows a site, forwards Tide requests to one egress.
    TideRelay(TideRelayConfig),
    /// Hysteria2 TCP-over-QUIC inbound.
    Hysteria2(Hysteria2InboundConfig),
    /// TUIC v5 authenticated QUIC inbound.
    Tuic(TuicInboundConfig),
    /// Full IP TUN inbound backed by the userspace TCP/UDP netstack.
    Tun(TunInboundConfig),
    /// A WireGuard server: peers' tunnelled IP packets are terminated in the
    /// same userspace netstack the TUN inbound uses.
    WireGuard(WireGuardInboundConfig),
    /// Dokodemo-door: a listener that takes whatever arrives for one fixed
    /// destination (DNS interception), or, with `follow_redirect`, for the
    /// destination a gateway rule redirected it from (see `Sockopt::tproxy`).
    Dokodemo {
        /// Xray's `address` / `rewriteAddress` and `port` / `rewritePort`.
        /// Both set, they are the fixed destination. With `follow_redirect`
        /// they replace just that part of the destination the connection was
        /// really addressed to.
        address: Option<Address>,
        port: Option<u16>,
        /// Xray's `portMap`: the destination for a connection that arrived on
        /// a given listening port. It wins over `address` and `port`.
        port_map: Vec<(u16, Address, u16)>,
        /// Which of TCP and UDP it listens for (Xray's `network`).
        tcp: bool,
        udp: bool,
        /// Xray's `followRedirect`: use the destination the connection was
        /// really addressed to (see `Sockopt::tproxy`).
        follow_redirect: bool,
    },
}

impl Inbound {
    /// Where a dokodemo connection should go. `original` is the destination a
    /// transparent connection was really addressed to, when there is one.
    /// `None` for any other kind of inbound, or when nothing names a
    /// destination.
    pub fn dokodemo_destination(
        &self,
        original: Option<std::net::SocketAddr>,
    ) -> Option<(Address, u16)> {
        let InboundProtocol::Dokodemo {
            address,
            port,
            port_map,
            ..
        } = &self.protocol
        else {
            return None;
        };
        if let Some((_, address, port)) = port_map.iter().find(|(from, ..)| *from == self.port) {
            return Some((address.clone(), *port));
        }
        match original {
            Some(found) => Some((
                address.clone().unwrap_or(Address::Ip(found.ip())),
                port.unwrap_or(found.port()),
            )),
            None => Some((address.clone()?, (*port)?)),
        }
    }
}

impl InboundProtocol {
    /// The protocol's name, for logs. Deliberately not the `Debug` form: that
    /// prints every user id and password the inbound holds, and a log is the
    /// last place those belong.
    pub fn kind(&self) -> &'static str {
        match self {
            InboundProtocol::Socks => "socks",
            InboundProtocol::Http => "http",
            InboundProtocol::Mixed => "mixed",
            InboundProtocol::Vless(_) => "vless",
            InboundProtocol::Trojan(_) => "trojan",
            InboundProtocol::Vmess(_) => "vmess",
            InboundProtocol::Shadowsocks(_) => "shadowsocks",
            InboundProtocol::AnyTls(_) => "anytls",
            InboundProtocol::Tide(_) => "zerov1",
            InboundProtocol::TideRelay(_) => "zerov1-relay",
            InboundProtocol::Hysteria2(_) => "hysteria2",
            InboundProtocol::Tuic(_) => "tuic",
            InboundProtocol::Tun(_) => "tun",
            InboundProtocol::Dokodemo { .. } => "dokodemo",
            InboundProtocol::WireGuard(_) => "wireguard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VlessInboundConfig {
    pub users: Box<[VlessInboundUser]>,
    /// Xray's `decryption`: the VLESS Encryption server setting
    /// (`mlkem768x25519plus.<mode>.<seconds>.<keys>`), or `None` for plain
    /// VLESS. Its contents are private keys and are checked when the inbound
    /// starts, not here.
    pub decryption: Option<Arc<str>>,
    /// Where a connection that is not a valid VLESS request is sent instead
    /// of being closed (Xray's `fallbacks`): usually a web server, so that a
    /// prober is answered by a real site.
    pub fallbacks: Box<[FallbackRule]>,
}

/// One entry of Xray's `fallbacks`: which unauthenticated connections it
/// takes (by the server name they asked for, the ALPN they negotiated and the
/// path of the HTTP request they opened with) and where they go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackRule {
    /// The TLS server name; `None` takes any.
    pub name: Option<Box<str>>,
    /// The negotiated ALPN protocol (`h2`, `http/1.1`); `None` takes any.
    pub alpn: Option<Box<str>>,
    /// The path of an HTTP/1 request the connection starts with; `None`
    /// takes any, including a connection that is not HTTP.
    pub path: Option<Box<str>>,
    pub dest: (Address, u16),
    /// The PROXY protocol version to send ahead of the connection (1 or 2),
    /// so the web server behind learns the real client; 0 sends none.
    pub xver: u8,
}

/// What is known about a connection when it is handed to a fallback.
#[derive(Debug, Clone, Default)]
pub struct FallbackProbe<'a> {
    pub server_name: Option<&'a str>,
    pub alpn: Option<&'a [u8]>,
    /// The first bytes the client sent.
    pub first_bytes: &'a [u8],
}

impl FallbackProbe<'_> {
    /// The request path if the first bytes are the start of an HTTP/1
    /// request, without its query.
    fn http_path(&self) -> Option<&str> {
        let line_end = self
            .first_bytes
            .iter()
            .position(|b| *b == b'\r' || *b == b'\n')?;
        let line = std::str::from_utf8(&self.first_bytes[..line_end]).ok()?;
        let mut parts = line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        (method.bytes().all(|b| b.is_ascii_uppercase())
            && version.starts_with("HTTP/")
            && target.starts_with('/'))
        .then(|| target.split(['?', '#']).next().unwrap_or(target))
    }
}

/// The rule that takes a connection, as Xray chooses: among the rules whose
/// conditions all hold, the one most particular about the name first, then
/// the ALPN, then the path; a rule with no conditions is the default.
pub fn select_fallback<'a>(
    rules: &'a [FallbackRule],
    probe: &FallbackProbe<'_>,
) -> Option<&'a FallbackRule> {
    let path = probe.http_path();
    rules
        .iter()
        .filter(|rule| {
            rule.name.as_deref().is_none_or(|name| {
                probe
                    .server_name
                    .is_some_and(|sni| sni.eq_ignore_ascii_case(name))
            }) && rule
                .alpn
                .as_deref()
                .is_none_or(|alpn| probe.alpn.is_some_and(|got| got == alpn.as_bytes()))
                && rule
                    .path
                    .as_deref()
                    .is_none_or(|wanted| path == Some(wanted))
        })
        .max_by_key(|rule| {
            (
                rule.name.is_some(),
                rule.alpn.is_some(),
                rule.path.is_some(),
            )
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessInboundUser {
    pub uuid: [u8; 16],
    pub flow: Flow,
    /// The `testseed` for this account's Vision padding: its own, or the
    /// inbound's.
    pub vision_seed: Option<[u32; 4]>,
    /// The account's name (Xray's `email`), what `user` routing rules and
    /// per-account figures refer to.
    pub email: Option<Arc<str>>,
    /// Xray's `reverse.tag` on an account: this account belongs to a
    /// reverse-proxy bridge. It may only dial in as one, and what it carries
    /// is reached by routing to an outbound of this tag.
    pub reverse: Option<Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrojanInboundConfig {
    pub password_hashes: Box<[[u8; 56]]>,
    /// The `email` of each client, in the order of `password_hashes`.
    pub emails: Box<[Option<Arc<str>>]>,
    /// Where a connection without a valid password is sent instead of being
    /// closed (Xray's `fallbacks`).
    pub fallbacks: Box<[FallbackRule]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VmessInboundConfig {
    pub users: Box<[VmessInboundUser]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessInboundUser {
    pub uuid: [u8; 16],
    pub cipher: VmessCipher,
    pub email: Option<Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksInboundConfig {
    pub method: ShadowsocksMethod,
    pub password: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnyTlsInboundConfig {
    pub passwords: Box<[Box<str>]>,
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct TideInboundConfig {
    /// The path prefix Tide requests are answered under; everything else
    /// gets the decoy page.
    pub path: Box<str>,
    /// The server's secret key. Its public half is what links carry.
    pub secret: [u8; 32],
    /// Users written in the config itself.
    pub users: Box<[TideUser]>,
    /// A file of more users that the control panel adds to and removes from.
    pub users_file: Option<Box<str>>,
    /// The name and port clients reach this server by, for the links the
    /// control panel makes. Without a name there are no links to show.
    pub public_host: Option<Box<str>>,
    pub public_port: u16,
    /// The secret path the control panel is served under; none, no panel.
    pub admin_path: Option<Box<str>>,
    pub shape: TideShape,
    /// Set when the inbound sits behind REALITY: what a client's link must
    /// carry to get through it.
    pub reality: Option<TideRealityLink>,
}

/// The parts of a ZeroV1 server's REALITY setup that its links repeat: the
/// name clients put in the hello, the secret their public key is made from,
/// and the first short id (empty when the server takes any).
#[derive(Clone, PartialEq, Eq)]
pub struct TideRealityLink {
    pub server_name: Box<str>,
    pub private_key: [u8; 32],
    pub short_id: Box<str>,
}

// The REALITY secret is the server's key: never in a log.
impl std::fmt::Debug for TideRealityLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TideRealityLink")
            .field("server_name", &self.server_name)
            .field("short_id", &self.short_id)
            .finish_non_exhaustive()
    }
}

/// A Tide relay: it holds no key and no user, only where the egress is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TideRelayConfig {
    /// The path prefix Tide requests are forwarded under; the egress's.
    pub path: Box<str>,
    pub upstream_address: Address,
    pub upstream_port: u16,
    /// The egress's site name, for TLS and for the requests passed on;
    /// the upstream address when not given.
    pub upstream_name: Option<Box<str>>,
    /// Extra certificate authorities to trust for the egress (DER), for one
    /// whose certificate a private CA issued. Ordinary roots still apply.
    pub upstream_roots: Vec<Box<[u8]>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TideUser {
    pub id: [u8; 16],
    pub name: Box<str>,
}

// The user id is this client's password on the server: never in a log. The
// whole value still has to tell two servers or two users apart where it is
// hashed into a cache key, so a short digest of the id stands in for it.
impl std::fmt::Debug for TideConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mark = self
            .user
            .iter()
            .zip(&self.server_key)
            .fold(0u64, |mark, (a, b)| {
                mark.wrapping_mul(0x100_0000_01b3) ^ u64::from(*a) ^ (u64::from(*b) << 8)
            });
        f.debug_struct("TideConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("split", &self.split)
            .field("packet_upload", &self.packet_upload)
            .field("datagrams", &self.datagrams)
            .field("rotate", &self.rotate)
            .field("tuning", &self.tuning)
            .field("identity", &format_args!("{mark:016x}"))
            .finish()
    }
}

// Configs are logged whole when a listener starts. A Tide config holds the
// server's secret key, every user's id (which is that user's password) and
// the control panel's secret path, so its debug form names them and shows
// none of them.
impl std::fmt::Debug for TideInboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TideInboundConfig")
            .field("path", &self.path)
            .field("users", &self.users.len())
            .field("users_file", &self.users_file)
            .field("public_host", &self.public_host)
            .field("public_port", &self.public_port)
            .field("panel", &self.admin_path.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TideUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TideUser")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hysteria2InboundConfig {
    pub passwords: Box<[Box<str>]>,
    /// Salamander password: every UDP datagram is obfuscated with it, and a
    /// client without it gets no answer at all.
    pub obfs_password: Option<Box<str>>,
    /// What a visitor who is not a Hysteria2 client is shown (Xray's
    /// `masquerade`); without it, a bare 404.
    pub masquerade: Option<Hysteria2Masquerade>,
}

/// The website a Hysteria2 server pretends to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Masquerade {
    /// One fixed response to every request (`type: "string"`).
    Text {
        status: u16,
        headers: Vec<(Box<str>, Box<str>)>,
        content: Box<str>,
    },
    /// A directory of static files (`type: "file"`, `dir`).
    Files { dir: Box<str> },
    /// Another site's pages, GET and HEAD only (`type: "proxy"`, `url`).
    Proxy { url: Box<str> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicInboundConfig {
    pub uuid: [u8; 16],
    pub password: Box<str>,
}

/// The WireGuard inbound (Xray's `wireguard` with `settings.peers`).
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardInboundConfig {
    pub secret_key: [u8; 32],
    /// The userspace stack's MTU: the packet size inside the tunnel.
    pub mtu: usize,
    pub peers: Box<[WireGuardPeer]>,
}

// The secret key is left out of the debug form, so a log line that prints a
// config does not print it.
impl std::fmt::Debug for WireGuardInboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardInboundConfig")
            .field("mtu", &self.mtu)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Addresses the peer may send from and be sent to (Xray's `allowedIPs`,
    /// all addresses when it is absent).
    pub allowed_ips: Box<[crate::routing::ipnet_lite::Cidr]>,
    pub keepalive: Option<u16>,
    pub email: Option<Arc<str>>,
}

impl std::fmt::Debug for WireGuardPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardPeer")
            .field("allowed_ips", &self.allowed_ips)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInboundConfig {
    pub name: Box<str>,
    pub mtu: usize,
    pub enable_tcp: bool,
    pub enable_udp: bool,
    pub enable_icmp: bool,
    /// Addresses to assign to the kernel TUN interface, in CIDR notation.
    pub addresses: Box<[Box<str>]>,
    /// Routes to install when `auto_route` is enabled, in CIDR notation.
    pub routes: Box<[Box<str>]>,
    pub auto_route: bool,
    pub strict_route: bool,
}

impl Default for TunInboundConfig {
    fn default() -> Self {
        Self {
            name: "zray0".into(),
            mtu: 1500,
            enable_tcp: true,
            enable_udp: true,
            enable_icmp: true,
            addresses: vec!["198.18.0.1/15".into()].into_boxed_slice(),
            routes: Box::new([]),
            auto_route: false,
            strict_route: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Inbound {
    pub tag: Arc<str>,
    pub listen: Address,
    pub port: u16,
    pub protocol: InboundProtocol,
    pub transport: Transport,
    pub raw_http_header: Option<RawHttpHeader>,
    pub security: InboundSecurity,
    pub sniffing: Sniffing,
    pub socks_auth: SocksAuth,
    /// The listener's socket settings and what is done to each connection it
    /// accepts (Xray's `streamSettings.sockopt` on an inbound).
    pub sockopt: Sockopt,
    /// Expect a PROXY protocol header (version 1 or 2) at the start of every
    /// connection, from a load balancer in front of this inbound, and take
    /// the client's address from it.
    pub accept_proxy_protocol: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SocksAuth {
    #[default]
    None,
    Password(Box<[SocksAccount]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksAccount {
    pub username: Box<str>,
    pub password: Box<str>,
}

/// Server-side protection is separate from outbound `Security`: a listener
/// owns certificate/key material, while a client only owns verification
/// parameters. Keeping the distinction in the compiled model prevents a
/// server from accidentally interpreting a public key as a certificate.
#[derive(Debug, Clone)]
pub enum InboundSecurity {
    None,
    Tls(InboundTlsConfig),
    Reality(InboundRealityConfig),
}

/// A certificate chain and its private key, as the bytes read from the config.
pub type CertificateAndKey = (Box<[u8]>, Box<[u8]>);

#[derive(Debug, Clone)]
pub struct InboundTlsConfig {
    pub certificate: Box<[u8]>,
    pub private_key: Box<[u8]>,
    pub alpn: Box<[Box<str>]>,
    /// More certificates and keys, one of which is chosen by the server name
    /// the client asks for; the first pair above is the default.
    pub extra_identities: Box<[CertificateAndKey]>,
    /// Xray's `rejectUnknownSni`: a hello naming something none of the
    /// certificates is valid for (or naming nothing) fails the handshake.
    pub reject_unknown_sni: bool,
}

#[derive(Debug, Clone)]
pub struct InboundRealityConfig {
    pub server_names: Box<[Box<str>]>,
    pub private_key: [u8; 32],
    pub short_ids: Box<[Box<[u8]>]>,
    pub target: Option<(Address, u16)>,
    /// Xray's `mldsa65Seed`: the server signs every handshake with an
    /// ML-DSA-65 key made from this seed, so a client holding the matching
    /// `mldsa65Verify` key can tell the real server from one that merely
    /// knows the x25519 key. A secret: it is never printed.
    pub mldsa65_seed: Option<Secret32>,
    /// How far the client's clock may differ from this server's, in
    /// milliseconds, before the handshake is treated as not REALITY (a
    /// replayed hello is the case this stops). 0 means no check.
    pub max_time_diff_ms: u64,
    /// The oldest and newest client versions accepted, as `[major, minor,
    /// patch]` from the session id. Unset means any.
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    /// The PROXY protocol version (1 or 2) to send to the target when a
    /// connection is handed to it, so the target sees the real client; 0
    /// sends none.
    pub fallback_xver: u8,
    /// Limits on what an unauthenticated client may move through the
    /// fallback: a rate-limited probe cannot be used to read a lot from
    /// the target or to feed it traffic.
    pub fallback_limit_up: FallbackLimit,
    pub fallback_limit_down: FallbackLimit,
}

/// Xray's `limitFallbackUpload` / `limitFallbackDownload`: after
/// `after_bytes`, the flow is held to `bytes_per_sec` (with a burst of
/// `burst_bytes_per_sec`). Zero in `bytes_per_sec` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

/// 32 secret bytes that print as nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret32(pub [u8; 32]);

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret32(..)")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sniffing {
    pub enabled: bool,
    pub sniff_http: bool,
    pub sniff_tls: bool,
    /// Read the server name from a QUIC Initial (RFC 9001) so a UDP flow to
    /// port 443 routes by domain like its TCP twin.
    pub sniff_quic: bool,
    /// When set, a sniffed domain informs routing but does not rewrite the
    /// destination.
    pub route_only: bool,
    /// Names that never steer a connection when sniffed (Xray's
    /// `domainsExcluded`): push services and the like that break if their
    /// address is replaced by what their TLS name resolves to. Same syntax
    /// as a routing rule's `domain`.
    pub domains_excluded: Box<[crate::routing::DomainPattern]>,
    /// Sniff only what is already known about the connection (Xray's
    /// `metadataOnly`): no bytes are read, so only FakeDNS can supply a name.
    pub metadata_only: bool,
}

impl Sniffing {
    /// What the first bytes of a connection say, with an excluded name
    /// dropped: the protocol label stays (a `bittorrent` or `tls` rule still
    /// matches) but the name never steers the connection.
    pub fn inspect(&self, bytes: &[u8]) -> zero_core::Sniffed {
        let mut sniffed = zero_core::sniff::inspect(bytes, self.sniff_http, self.sniff_tls);
        if sniffed.domain.as_deref().is_some_and(|d| self.excludes(d)) {
            sniffed.domain = None;
        }
        sniffed
    }

    /// Whether `domain` is on the `domainsExcluded` list. Geosite patterns
    /// are not evaluated here (no geodata at this layer) and never exclude.
    pub fn excludes(&self, domain: &str) -> bool {
        use crate::routing::DomainPattern as P;
        let domain = domain.to_ascii_lowercase();
        self.domains_excluded.iter().any(|pattern| match pattern {
            P::Full(name) => domain == **name,
            P::Suffix(name) => {
                domain == **name
                    || domain
                        .strip_suffix(&**name)
                        .is_some_and(|rest| rest.ends_with('.'))
            }
            P::Keyword(word) => domain.contains(&**word),
            P::Regex(_) | P::Geosite(_) => false,
        })
    }
}

// ------------------------------------------------------------------ policy

/// Xray's connection policy for level 0, the only level accounts here have.
/// Every value defaults to what the runtime already did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Everything a client does before its first proxied byte: the TLS
    /// handshake, the transport upgrade, the request header.
    pub handshake: Duration,
    /// A connection that moves no byte in either direction this long is closed.
    pub conn_idle: Duration,
    /// After one direction has finished, how long the other may stay silent.
    /// Xray names the two cases `uplinkOnly` and `downlinkOnly`; here the
    /// longer of the two is used for both.
    pub half_close: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(60),
            conn_idle: Duration::from_secs(300),
            half_close: Duration::from_secs(1),
        }
    }
}

// ------------------------------------------------------------------ runtime

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// How long a connection may sit idle, and how long a client may take to
    /// start talking (Xray's `policy.levels."0"`).
    pub policy: Policy,
    pub inbounds: Box<[Inbound]>,
    pub outbounds: Box<[Outbound]>,
    pub routing: crate::routing::Routing,
    pub dns: crate::dns::DnsSettings,
    pub observatory: Option<ObservatoryConfig>,
    /// Routing rule-set files the runtime keeps current. Absent means the host
    /// application supplies geodata itself.
    pub assets: Option<AssetsConfig>,
    pub log_level: Box<str>,
    /// Reverse-proxy bridges (Xray's `reverse.bridges`): each keeps a
    /// connection open to its portal and serves what comes back down it.
    pub bridges: Box<[ReverseBridge]>,
}

/// One reverse-proxy bridge. Its connections to the portal are routed as if
/// they had arrived on an inbound called `tag`, addressed to `domain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseBridge {
    pub tag: Arc<str>,
    pub domain: Arc<str>,
    /// For a VLESS account's `reverse`: the outbound that dials the portal
    /// with the reverse command. Without it the dial is routed (`domain`).
    pub via: Option<Arc<str>>,
}

/// Where routing rule sets come from and how often they are refreshed.
///
/// Mirrors are ordered and tried in turn. A `sha256` pin makes an otherwise
/// untrusted mirror usable, because a mirror that serves different bytes is
/// rejected before the file is ever installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetsConfig {
    pub directory: Option<Arc<str>>,
    pub refresh_interval: Duration,
    pub retry_interval: Duration,
    pub max_bytes: usize,
    pub timeout: Duration,
    /// Refresh on startup even when the cache is inside its TTL.
    pub refresh_on_start: bool,
    /// Download updates at all. Off, the files already in `directory` are
    /// loaded and never replaced: for a host that ships its own rule sets
    /// (the Android app bundles trimmed ones) and must not spend a metered,
    /// filtered connection re-fetching the full upstream lists.
    pub auto_update: bool,
    pub files: Box<[AssetFile]>,
}

impl Default for AssetsConfig {
    fn default() -> Self {
        Self {
            directory: None,
            refresh_interval: Duration::from_secs(24 * 60 * 60),
            retry_interval: Duration::from_secs(15 * 60),
            max_bytes: 64 * 1024 * 1024,
            timeout: Duration::from_secs(120),
            refresh_on_start: false,
            auto_update: true,
            files: Box::from([]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetFileKind {
    Geosite,
    Geoip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetFile {
    pub name: Arc<str>,
    pub kind: AssetFileKind,
    pub urls: Box<[Arc<str>]>,
    pub sha256: Option<Arc<str>>,
}

/// Active, bounded endpoint probes for least-ping/least-load balancers.
/// `probe_url` is an operator-selected health URL; no browsing destination or
/// response body is persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryConfig {
    pub probe_url: Arc<str>,
    pub probe_interval: Duration,
    pub subject_selector: Box<[Box<str>]>,
    /// Optional bounded CDN-edge candidates. These are probed with the
    /// configured Host header and ranked by application response progress.
    pub clean_ip: Option<CleanIpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanIpConfig {
    pub candidates: Box<[std::net::SocketAddr]>,
    pub host: Arc<str>,
    pub path: Arc<str>,
}

/// The immutable graph handed to the runtime after parsing and validation.
///
/// `RuntimeConfig` remains the convenient, inspectable representation used by
/// the JSON and link front ends. `RuntimeGeneration` is the actual compiler
/// boundary: it assigns stable numeric ids and materialises balancer members
/// once, so request handling never has to scan configuration strings.
#[derive(Debug, Clone)]
pub struct RuntimeGeneration {
    pub id: zero_core::GenerationId,
    pub config: Arc<RuntimeConfig>,
    outbound_tags: BTreeMap<Box<str>, OutboundId>,
    balancer_members: Box<[Box<[OutboundId]>]>,
}

impl RuntimeGeneration {
    pub fn compile(config: RuntimeConfig, id: zero_core::GenerationId) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let outbound_tags = config
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| {
                (
                    outbound.tag.to_string().into_boxed_str(),
                    OutboundId(index as u32),
                )
            })
            .collect();
        let balancer_members = config
            .routing
            .balancers
            .iter()
            .map(|balancer| config.expand_balancer(balancer).into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            id,
            config,
            outbound_tags,
            balancer_members,
        })
    }

    pub fn outbound_id(&self, tag: &str) -> Option<OutboundId> {
        self.outbound_tags.get(tag).copied()
    }

    pub fn balancer_ids(&self, tag: &str) -> Option<&[OutboundId]> {
        self.config
            .routing
            .balancers
            .iter()
            .position(|balancer| balancer.tag.as_ref() == tag)
            .and_then(|index| self.balancer_members.get(index).map(|ids| ids.as_ref()))
    }
}

impl RuntimeConfig {
    pub fn outbound_by_tag(&self, tag: &str) -> Option<&Outbound> {
        self.outbounds.iter().find(|o| o.tag.as_ref() == tag)
    }

    /// The first outbound is the default when no rule matches.
    pub fn default_outbound(&self) -> Option<&Outbound> {
        self.outbounds.first()
    }

    pub fn balancer_by_tag(&self, tag: &str) -> Option<&crate::routing::Balancer> {
        self.routing
            .balancers
            .iter()
            .find(|b| b.tag.as_ref() == tag)
    }

    /// Expand a balancer's tag prefixes against the outbound table.
    ///
    /// Xray matches selectors as prefixes, and the expansion is done once at
    /// compile time so selection never walks strings on the hot path. A
    /// selector is authoritative: a deliberately tagged Freedom outbound is
    /// a valid member, while DNS and Blackhole cannot carry a routed session.
    pub fn expand_balancer(&self, b: &crate::routing::Balancer) -> Vec<OutboundId> {
        let mut out: Vec<OutboundId> = self
            .outbounds
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                !matches!(
                    &o.protocol,
                    OutboundProtocol::Dns { .. } | OutboundProtocol::Blackhole { .. }
                ) && b.selector.iter().any(|sel| o.tag.starts_with(sel.as_ref()))
            })
            .map(|(i, _)| OutboundId(i as u32))
            .collect();
        out.sort_by_key(|id| self.outbounds[id.0 as usize].tag.clone());
        out
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.outbounds.is_empty() {
            return Err("configuration has no outbounds".into());
        }
        for o in self.outbounds.iter() {
            o.validate()?;
        }
        for rule in self.routing.rules.iter() {
            match &rule.target {
                crate::routing::RuleTarget::Outbound(tag) => {
                    // Xray and v2rayA reserve the synthetic `api` or `api-out` target for
                    // their management service. It is not part of the user
                    // outbound table, but accepting it is necessary for
                    // otherwise valid configs that route an `api` inbound.
                    let tag_s = tag.as_ref();
                    let reserved_api = (tag_s == "api" || tag_s == "api-out")
                        && rule.inbound_tags.iter().any(|inbound| {
                            let i = inbound.as_ref();
                            i == "api" || i == "api-in"
                        });
                    if self.outbound_by_tag(tag).is_none() && !reserved_api {
                        return Err(format!("routing rule targets unknown outbound {tag:?}"));
                    }
                }
                crate::routing::RuleTarget::Balancer(tag)
                    if self.balancer_by_tag(tag).is_none() =>
                {
                    return Err(format!("routing rule targets unknown balancer {tag:?}"));
                }
                crate::routing::RuleTarget::DirectVia { resolver }
                    if !self
                        .dns
                        .servers
                        .iter()
                        .any(|server| server.tag.as_deref() == Some(resolver.as_ref())) =>
                {
                    return Err(format!(
                        "routing rule targets unknown DNS resolver tag {resolver:?}"
                    ));
                }
                _ => {}
            }
        }
        for b in self.routing.balancers.iter() {
            if let Some(fallback) = &b.fallback {
                if self.outbound_by_tag(fallback).is_none() {
                    return Err(format!(
                        "balancer {:?} has an unknown fallbackTag {fallback:?}",
                        b.tag
                    ));
                }
            }
            if self.expand_balancer(b).is_empty() {
                return Err(format!(
                    "balancer {:?} selects no outbound (selector {:?})",
                    b.tag, b.selector
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges() {
        assert_eq!(RangeU32::parse("100-200"), Some(RangeU32::new(100, 200)));
        assert_eq!(RangeU32::parse("1"), Some(RangeU32::new(1, 1)));
        assert_eq!(RangeU32::parse("x"), None);
    }

    #[test]
    fn inverted_range_is_normalized() {
        let r = RangeU32::new(200, 100);
        assert_eq!(r.min, 200);
        assert_eq!(r.max, 200);
    }

    #[test]
    fn websocket_refuses_reality_and_vision() {
        let caps = Transport::WebSocket(WebSocketConfig::default()).capabilities();
        assert!(!caps.supports_reality);
        assert!(!caps.supports_vision);
        assert!(Transport::Raw.capabilities().supports_reality);
    }

    #[test]
    fn fingerprint_parsing() {
        assert_eq!(Fingerprint::parse("chrome"), Some(Fingerprint::Chrome));
        assert_eq!(Fingerprint::parse("Chrome"), Some(Fingerprint::Chrome));
        assert_eq!(
            Fingerprint::parse("randomized"),
            Some(Fingerprint::Randomized)
        );
        assert_eq!(
            Fingerprint::parse("hellochrome_120_pq"),
            Some(Fingerprint::Named(Arc::from("hellochrome_120_pq")))
        );
        assert_eq!(
            Fingerprint::parse("hellochrome_155"),
            Some(Fingerprint::Named(Arc::from("hellochrome_155")))
        );
        assert!(Fingerprint::parse("hellochrome_155")
            .unwrap()
            .supports_reality());
        assert!(!Fingerprint::parse("hello360_auto")
            .unwrap()
            .supports_reality());
        assert!(Fingerprint::parse("hellochrome_120_pq")
            .unwrap()
            .supports_reality());
        assert_eq!(Fingerprint::parse("nope"), None);
    }

    #[test]
    fn flow_parsing() {
        assert_eq!(Flow::parse("xtls-rprx-vision"), Some(Flow::Vision));
        assert!(Flow::parse("xtls-rprx-vision").unwrap().is_vision());
        assert_eq!(Flow::parse(""), Some(Flow::None));
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    fn rule(name: Option<&str>, alpn: Option<&str>, path: Option<&str>, port: u16) -> FallbackRule {
        FallbackRule {
            name: name.map(Box::from),
            alpn: alpn.map(Box::from),
            path: path.map(Box::from),
            dest: (Address::parse_host("127.0.0.1"), port),
            xver: 0,
        }
    }

    fn pick(
        rules: &[FallbackRule],
        sni: Option<&str>,
        alpn: Option<&[u8]>,
        first: &[u8],
    ) -> Option<u16> {
        select_fallback(
            rules,
            &FallbackProbe {
                server_name: sni,
                alpn,
                first_bytes: first,
            },
        )
        .map(|rule| rule.dest.1)
    }

    #[test]
    fn the_most_particular_rule_that_holds_wins() {
        let rules = [
            rule(None, None, None, 1),
            rule(None, None, Some("/ws"), 2),
            rule(None, Some("h2"), None, 3),
            rule(Some("a.example"), None, None, 4),
        ];
        let http = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();
        // Nothing particular: the default.
        assert_eq!(pick(&rules, None, None, &http("/")), Some(1));
        // The path.
        assert_eq!(pick(&rules, None, Some(b"http/1.1"), &http("/ws")), Some(2));
        // The ALPN beats the path; the name beats both.
        assert_eq!(pick(&rules, None, Some(b"h2"), &http("/ws")), Some(3));
        assert_eq!(
            pick(&rules, Some("A.Example"), Some(b"h2"), &http("/ws")),
            Some(4)
        );
        // A name that is not the one asked for does not apply.
        assert_eq!(pick(&rules, Some("b.example"), None, &http("/")), Some(1));
    }

    #[test]
    fn without_a_default_an_unmatched_connection_has_nowhere_to_go() {
        let rules = [rule(None, None, Some("/ws"), 2)];
        assert_eq!(pick(&rules, None, None, b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(pick(&rules, None, None, b"not http"), None);
        assert_eq!(
            pick(&rules, None, None, b"GET /ws HTTP/1.1\r\n\r\n"),
            Some(2)
        );
        assert_eq!(pick(&[], None, None, b"GET / HTTP/1.1\r\n\r\n"), None);
    }
}
