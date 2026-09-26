//! The compiled configuration.
//!
//! This is deliberately *not* the shape of the JSON. Parsing produces this,
//! and the runtime only ever sees this: immutable, string-interned where it
//! matters, with invalid protocol/transport combinations already rejected
//! (RESEARCH-01 §4, §19).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use zero_core::{Address, Network, OutboundId};

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
}

impl Security {
    pub fn name(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls(_) => "tls",
            Security::Reality(_) => "reality",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsConfig {
    pub server_name: Option<Arc<str>>,
    pub alpn: Vec<Box<str>>,
    pub fingerprint: Fingerprint,
    /// Canonical Xray `allowInsecure`. Kept so the parser can fail closed on
    /// `true` rather than silently ignoring it.
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// TLS-encoded ECHConfigList bytes after base64 decoding.
    pub config_list: Box<[u8]>,
    /// Inner SNI. When omitted, the ordinary TLS `serverName` is used.
    pub server_name: Option<Arc<str>>,
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
    pub udp_noise: Vec<NoiseConfig>,
    /// Optional Linux raw-packet fake-SNI injection selected by the planner.
    pub sni_desync: Option<SniDesyncConfig>,
    /// Optional keepalive shaping for a network that resets flows on a time
    /// threshold rather than a byte threshold (PLAN-01 §5.2).
    pub keepalive: Option<KeepaliveConfig>,
}

impl Evasion {
    pub fn is_empty(&self) -> bool {
        self.tcp_fragment.is_none()
            && self.udp_noise.is_empty()
            && self.sni_desync.is_none()
            && self.keepalive.is_none()
    }
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
}

impl Default for SniDesyncConfig {
    fn default() -> Self {
        Self {
            fake_sni: "www.microsoft.com".into(),
            sequence: 0,
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
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            packets: FragmentPackets::TlsHello,
            length: RangeU32::new(100, 200),
            delay: RangeDuration::millis(1, 1),
            max_split: RangeU32::new(0, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPackets {
    /// Fragment only the TLS ClientHello — cheapest and the BPB default.
    TlsHello,
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
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            transport: Transport::Raw,
            security: Security::None,
            sockopt: Sockopt::default(),
            evasion: Evasion::default(),
            raw_http_header: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Freedom {
        domain_strategy: DomainStrategy,
    },
    Blackhole,
    /// Hijacks DNS queries routed to it.
    Dns,
    Vless(VlessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    Vmess(VmessConfig),
    /// AnyTLS v2 over ordinary certificate TLS.
    AnyTls(AnyTlsConfig),
    /// Hysteria2 TCP over QUIC/HTTP3.
    Hysteria2(Hysteria2Config),
    /// TUIC v5 over authenticated QUIC.
    Tuic(TuicConfig),
    /// WireGuard/AmneziaWG UDP tunnel. TCP destinations are rejected at the
    /// runtime boundary because this protocol carries IP packets, not a byte
    /// stream.
    AmneziaWireguard(AmneziaWireguardConfig),
}

impl OutboundProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            OutboundProtocol::Freedom { .. } => "freedom",
            OutboundProtocol::Blackhole => "blackhole",
            OutboundProtocol::Dns => "dns",
            OutboundProtocol::Vless(_) => "vless",
            OutboundProtocol::Trojan(_) => "trojan",
            OutboundProtocol::Shadowsocks(_) => "shadowsocks",
            OutboundProtocol::Vmess(_) => "vmess",
            OutboundProtocol::AnyTls(_) => "anytls",
            OutboundProtocol::Hysteria2(_) => "hysteria2",
            OutboundProtocol::Tuic(_) => "tuic",
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
                | OutboundProtocol::Hysteria2(_)
                | OutboundProtocol::Tuic(_)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Config {
    pub address: Address,
    pub port: u16,
    pub password: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicConfig {
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
}

impl Outbound {
    /// Reject combinations that cannot work, before any socket is opened.
    pub fn validate(&self) -> Result<(), String> {
        let caps = self.stream.transport.capabilities();

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

        if self.stream.evasion.sni_desync.is_some()
            && matches!(self.stream.security, Security::None)
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
            if !self.stream.evasion.is_empty() || self.stream.raw_http_header.is_some() {
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
            if !self.stream.evasion.is_empty() || self.stream.raw_http_header.is_some() {
                return Err(format!(
                    "outbound {}: TUIC cannot carry TCP finalmask or raw HTTP camouflage",
                    self.tag
                ));
            }
        }

        if let OutboundProtocol::AmneziaWireguard(wireguard) = &self.protocol {
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

        if let Security::Tls(t) = &self.stream.security {
            if t.allow_insecure {
                return Err(format!(
                    "outbound {}: allowInsecure is refused; it disables certificate verification",
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

    /// The remote endpoint this outbound dials, if any.
    pub fn endpoint(&self) -> Option<(Address, u16)> {
        match &self.protocol {
            OutboundProtocol::Vless(v) => Some((v.address.clone(), v.port)),
            OutboundProtocol::Trojan(t) => Some((t.address.clone(), t.port)),
            OutboundProtocol::Shadowsocks(s) => Some((s.address.clone(), s.port)),
            OutboundProtocol::Vmess(v) => Some((v.address.clone(), v.port)),
            OutboundProtocol::AnyTls(a) => Some((a.address.clone(), a.port)),
            OutboundProtocol::Hysteria2(h) => Some((h.address.clone(), h.port)),
            OutboundProtocol::Tuic(t) => Some((t.address.clone(), t.port)),
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
    /// Hysteria2 TCP-over-QUIC inbound.
    Hysteria2(Hysteria2InboundConfig),
    /// TUIC v5 authenticated QUIC inbound.
    Tuic(TuicInboundConfig),
    /// Full IP TUN inbound backed by the userspace TCP/UDP netstack.
    Tun(TunInboundConfig),
    /// Fixed-destination listener, used for DNS interception.
    Dokodemo {
        target: Option<(Address, u16)>,
        network: Network,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VlessInboundConfig {
    pub users: Box<[VlessInboundUser]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessInboundUser {
    pub uuid: [u8; 16],
    pub flow: Flow,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrojanInboundConfig {
    pub password_hashes: Box<[[u8; 56]]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VmessInboundConfig {
    pub users: Box<[VmessInboundUser]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmessInboundUser {
    pub uuid: [u8; 16],
    pub cipher: VmessCipher,
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hysteria2InboundConfig {
    pub passwords: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicInboundConfig {
    pub uuid: [u8; 16],
    pub password: Box<str>,
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

#[derive(Debug, Clone)]
pub struct InboundTlsConfig {
    pub certificate: Box<[u8]>,
    pub private_key: Box<[u8]>,
    pub alpn: Box<[Box<str>]>,
}

#[derive(Debug, Clone)]
pub struct InboundRealityConfig {
    pub server_names: Box<[Box<str>]>,
    pub private_key: [u8; 32],
    pub short_ids: Box<[Box<[u8]>]>,
    pub target: Option<(Address, u16)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sniffing {
    pub enabled: bool,
    pub sniff_http: bool,
    pub sniff_tls: bool,
    /// When set, a sniffed domain informs routing but does not rewrite the
    /// destination.
    pub route_only: bool,
}

// ------------------------------------------------------------------ runtime

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub inbounds: Box<[Inbound]>,
    pub outbounds: Box<[Outbound]>,
    pub routing: crate::routing::Routing,
    pub dns: crate::dns::DnsSettings,
    pub observatory: Option<ObservatoryConfig>,
    /// Routing rule-set files the runtime keeps current. Absent means the host
    /// application supplies geodata itself.
    pub assets: Option<AssetsConfig>,
    pub log_level: Box<str>,
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
                    OutboundProtocol::Dns | OutboundProtocol::Blackhole
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
