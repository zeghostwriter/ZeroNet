//! `buildConfig`: the app's settings screen, turned into a runtime config.
//!
//! The app never writes Xray JSON itself. It sends a small `BuildRequest`
//! (links, mode, a few toggles) and gets back a complete configuration built
//! on [`zero_config::IranPreset`] — the same preset the desktop tools use, so
//! the routing, DNS tiers and sanction handling are identical everywhere —
//! with the mobile specifics layered on:
//!
//! * a `tun` inbound whose addresses match what the app gives
//!   `VpnService.Builder`, and a `dns` outbound that answers the tunnel's
//!   UDP/53 from the runtime's own resolver (see `zero_runtime::dns_out`);
//! * one outbound per link (`proxy`, `proxy-1`, …) and, with more than one, a
//!   `leastPing` balancer fed by the observatory, so a dying server is routed
//!   around in-process;
//! * the LAN-sharing, QUIC-blocking and evasion toggles.
//!
//! The result is compiled with `zero_config::compile_config` before it is
//! returned: a config that would not start is reported as an error here, where
//! the app can show it, rather than as a failed `start`.
//!
//! **FakeDNS** (`dns.fakedns`, VPN mode only): a catch-all `fakedns` server
//! goes in front of the encrypted remote tier, so an application's query for
//! a foreign name is answered at once with a synthetic 198.18.0.0/15 address
//! and the name itself travels to the proxy, which resolves it on the far
//! side: no DNS round trip through the tunnel before every new site, and no
//! answer for a filtered resolver to poison. Domain-scoped tiers (domestic
//! names, sanctioned names) still get real answers, so direct routing by
//! address keeps working. The runtime answers only the applications from
//! FakeDNS; its own lookups (proxy server names, direct connections) use a
//! view of the resolver without it (`zero_dns::Resolver::without_fake`).

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use zero_config::presets::{IRAN_DIRECT_DOMAINS, IRAN_DIRECT_IPS};
use zero_config::{IranPreset, LocalDns, RemoteDns};

/// Addresses of the TUN interface, matching the app's `VpnService.Builder`.
pub const TUN_ADDRESS_V4: &str = "172.19.0.1/30";
pub const TUN_ADDRESS_V6: &str = "fdfe:dcba:9876::1/126";
/// The observatory's probe for balancer ranking.
pub const BALANCER_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

/// The shaped variants `evasion = "auto"` adds after each link's plain one:
/// [`EMPTY_RECORD`], then TCP segments of 40-80 bytes.
///
/// Which one gets through depends on the day. From Center, segments of 40-80
/// got 10 of 10 through a throttled Cloudflare edge on 2026-09-28; on
/// 2026-10-07 they got 0 of 2 and the empty record got 2 of 2. Both stay, the
/// balancer's probes keep whichever works, and every variant is one more
/// outbound to probe, so there are two and not a sweep.
const AUTO_FRAGMENT_LENGTHS: [&str; 2] = [EMPTY_RECORD, "40-80"];
/// Stands in for a length: one empty TLS record in front of the ClientHello,
/// in the same write (`zero_config::FragmentConfig::empty_record`).
const EMPTY_RECORD: &str = "empty";

/// What the builder does about XHTTP connection reuse (`xmux` in the
/// request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Xmux {
    /// A connection per proxied request on every variant.
    Off,
    /// Each link's own reuse settings, or Xray's defaults.
    On,
    /// A reusing variant beside the others under `evasion = "auto"`; `On`
    /// without it.
    Auto,
}

/// How much the builder layers ClientHello fragmentation onto TLS links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evasion {
    /// No fragmentation; the link dials as described.
    Off,
    /// Each fragmentable link as is, then shaped each way in
    /// `AUTO_FRAGMENT_LENGTHS`, behind the balancer: the plain connection is
    /// used while it works, and a fragmented one takes over when it does not.
    /// When other users on this network reported fragmenting working better
    /// (`fragment_first`), the fragmented variants come first instead.
    Auto,
    /// Every fragmentable link fragmented, always (40-80).
    Strong,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct BuildRequest {
    links: Vec<String>,
    mode: String,
    tun: TunRequest,
    socks_port: u16,
    http_port: u16,
    lan: LanRequest,
    iran_direct: bool,
    block_ads: bool,
    block_quic: bool,
    evasion: String,
    /// ClientHello fragment packets for `auto`/`strong` evasion: a write
    /// range, `1-1` by default (plain TCP segments of the ClientHello), or
    /// `tlshello` (TLS record re-framing), which stopped getting through in
    /// Iran — 0 of 3 against 3 of 3, measured 2026-09-28 — or `tlssni` (TLS
    /// record re-framing with the cut inside the server name), for a filter
    /// that reassembles TCP but reads the name from one TLS record.
    fragment_packets: String,
    /// Put the fragmented variants of `auto` first: the app sets this when
    /// the crowd rankings say fragmenting works better than a plain
    /// connection on this network, so a fresh connect starts with what
    /// worked for others instead of rediscovering it.
    fragment_first: bool,
    /// Send a decoy ClientHello naming an allowed site ahead of the real one
    /// on every TLS/REALITY outbound. The engine sends it with a raw socket
    /// where it may open one and from the connection's own socket otherwise
    /// (`zero_evasion::decoy`); where neither works it falls back to
    /// fragmentation.
    sni_spoof: bool,
    /// Whether `evasion = "auto"` adds the variants of each link that hide
    /// its server name (an urgent byte, a decoy). Left out, the device is
    /// asked which of them it can do.
    auto_decoy: Option<bool>,
    /// The hop limit for a decoy that has to expire on the way, on a device
    /// whose kernel has no MD5 option to stop it with. Zero turns the TTL
    /// decoy off. Used by `sni_spoof` on such a device, and by the variant
    /// `auto` adds for it.
    decoy_ttl: u8,
    /// Whether `auto` adds the TTL-decoy variant. Left out, the device is
    /// asked (it is added only where the kernel has no MD5 option).
    auto_ttl_decoy: Option<bool>,
    /// Whether `auto` adds the Fast Open variant (the hello in the SYN).
    /// Left out, the device is asked: it needs a kernel with
    /// `TCP_FASTOPEN_CONNECT`, and a TLS port to dial.
    auto_fast_open: Option<bool>,
    /// Whether `auto` adds the record-version variant (another version in
    /// the first record header). Left out, it is added where name hiding is
    /// on: it needs nothing
    /// from the device but the name-hiding switch.
    auto_record: Option<bool>,
    /// Reuse of XHTTP's HTTP/2 connections (XMUX): `off` (a connection per
    /// proxied request, as before), `on` (what each link says, or Xray's
    /// defaults), or `auto`, which under `evasion = "auto"` adds a reusing
    /// variant beside the others and lets the balancer's probes decide, and
    /// is `on` otherwise. Reuse that stalls on this network switches itself
    /// off per server either way (see `zero_runtime`'s XMUX pool).
    xmux: String,
    dns: DnsRequest,
    log_level: String,
    /// Scanner results (`ip:port`), ranked by the observatory for CDN-fronted
    /// outbounds.
    clean_ips: Vec<String>,
    /// Where `geosite.dat`/`geoip.dat` live. Normally supplied by the host
    /// (`dataDir/assets`), not by the request.
    assets_dir: Option<PathBuf>,
    /// The order every WARP account in `links` runs in, overriding what its
    /// link says: `server-first` (hybrid) or `warp-first` (reverse hybrid).
    /// Unset, or `auto`, keeps each link's own order.
    warp_order: Option<String>,
    /// A password for the app's own use of the local proxy in VPN mode (see
    /// [`LocalAuth`]). Empty leaves the local proxy open, as before.
    local_auth: LocalAuth,
    /// The rules of the user's routing profile, tried before the built-in
    /// ones (`zero_config::UserRule`).
    routing_rules: Vec<zero_config::UserRule>,
    /// The user's "Allow insecure" switch: every link's certificate check is
    /// skipped, not only those whose link asks for it. Reaches more servers
    /// (self-signed, expired, wrong name) at the price of trusting whoever
    /// answers. Off unless the user turned it on.
    allow_insecure: bool,
}

/// The password the host app will use on its own requests through the local
/// HTTP proxy.
///
/// How this is used: in VPN mode other apps reach the tunnel through the TUN
/// device, so the local proxy ports serve only the host app's own checks.
/// Left open on loopback they also serve every other app on the device: any
/// of them can connect, ask a what-is-my-address service through the proxy,
/// and learn the address of the server the user is hiding behind. Tools that
/// do exactly this to common clients are public. Given a password, VPN mode
/// drops the SOCKS port (nothing of the host's uses it) and makes the HTTP
/// port refuse anyone without it.
///
/// It does nothing in proxy mode, or when the user is sharing the connection
/// on the LAN: there the ports are meant for others, on the user's terms.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LocalAuth {
    user: String,
    pass: String,
}

impl Default for BuildRequest {
    fn default() -> Self {
        Self {
            links: Vec::new(),
            mode: "vpn".into(),
            tun: TunRequest::default(),
            socks_port: 10808,
            http_port: 10809,
            lan: LanRequest::default(),
            iran_direct: true,
            block_ads: true,
            block_quic: true,
            evasion: "auto".into(),
            fragment_packets: "1-1".into(),
            fragment_first: false,
            sni_spoof: false,
            auto_decoy: None,
            decoy_ttl: zero_evasion::decoy::DEFAULT_TTL,
            auto_ttl_decoy: None,
            auto_fast_open: None,
            auto_record: None,
            xmux: "auto".into(),
            dns: DnsRequest::default(),
            log_level: "warning".into(),
            clean_ips: Vec::new(),
            assets_dir: None,
            warp_order: None,
            local_auth: LocalAuth::default(),
            routing_rules: Vec::new(),
            allow_insecure: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct TunRequest {
    mtu: u32,
    ipv6: bool,
}

impl Default for TunRequest {
    fn default() -> Self {
        Self {
            mtu: 1500,
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct LanRequest {
    enabled: bool,
    listen: String,
    user: String,
    pass: String,
}

impl Default for LanRequest {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0".into(),
            user: String::new(),
            pass: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct DnsRequest {
    remote: String,
    /// Optional user-supplied resolver, overriding `remote`. Any form the
    /// runtime's `ResolverEndpoint::parse` accepts (a bare IP such as
    /// `8.8.8.8`, or `tls://…`, `https://…/dns-query`, …). Empty means "use
    /// `remote`".
    custom: String,
    local: String,
    /// Optional user-supplied resolver for Iranian names, overriding `local`.
    /// The same forms and rule as `custom` (an IP, or an IP-addressed
    /// `tls://` / `https://` URL). Empty means "use `local`".
    custom_local: String,
    /// The Iranian anti-sanction resolver: a built-in name
    /// (`shecan`/`electro`/`begzar`/`radar`), or `none`/`off` to disable the
    /// third verdict. Sanctioned services resolve here and route direct.
    anti_sanction: String,
    /// Optional user-supplied anti-sanction resolver, overriding
    /// `anti_sanction`. A bare IP or an IP-addressed DoH/DoT/DoQ URL; a
    /// hostname is refused (the censored network cannot bootstrap it). Empty
    /// means "use `anti_sanction`".
    custom_anti_sanction: String,
    fakedns: bool,
}

impl Default for DnsRequest {
    fn default() -> Self {
        Self {
            remote: "google".into(),
            custom: String::new(),
            local: "google".into(),
            custom_local: String::new(),
            anti_sanction: "auto".into(),
            custom_anti_sanction: String::new(),
            fakedns: true,
        }
    }
}

/// Build from a request, taking the asset directory from the request itself
/// (`assets_dir`), if it names one.
pub fn build_config(request: &Value) -> Result<Value, String> {
    build_config_with_assets(request, None)
}

/// Build from a request. `assets_dir` (the host's `dataDir/assets`) is used
/// when the request does not name one; managed geodata is enabled only when
/// both `geosite.dat` and `geoip.dat` are already present there.
pub fn build_config_with_assets(
    request: &Value,
    assets_dir: Option<&Path>,
) -> Result<Value, String> {
    let request: BuildRequest = serde_json::from_value(request.clone())
        .map_err(|error| format!("invalid request: {error}"))?;
    let vpn = match request.mode.as_str() {
        "vpn" => true,
        "proxy" => false,
        other => return Err(format!("mode must be \"vpn\" or \"proxy\", got {other:?}")),
    };
    if request.links.is_empty() {
        return Err("at least one link is required".into());
    }
    let evasion = match request.evasion.as_str() {
        "off" => Evasion::Off,
        // "smart" was a separate mode before it and "auto" became one.
        "auto" | "smart" => Evasion::Auto,
        "strong" => Evasion::Strong,
        other => {
            return Err(format!(
                "evasion must be \"off\", \"auto\" or \"strong\", got {other:?}"
            ))
        }
    };
    // Fragment packets for auto/strong evasion: a write-count range (`1-1`,
    // the default), `tlshello` (TLS record re-framing) or `tlssni` (re-framing
    // with the cut inside the server name). Validated here so the error names
    // the field rather than surfacing from the compiler.
    let fragment_packets = {
        let value = request.fragment_packets.trim();
        if value.is_empty() {
            "1-1".to_string()
        } else if value == "tlshello"
            || value == "tlssni"
            || zero_config::RangeU32::parse(value).is_some()
        {
            value.to_string()
        } else {
            return Err(format!(
                "fragment_packets must be \"tlshello\", \"tlssni\" or a range like \"1-1\", got {value:?}"
            ));
        }
    };
    let xmux = match request.xmux.as_str() {
        "" | "auto" => Xmux::Auto,
        "on" => Xmux::On,
        "off" => Xmux::Off,
        other => {
            return Err(format!(
                "xmux must be \"auto\", \"on\" or \"off\", got {other:?}"
            ))
        }
    };
    let remote_dns = RemoteDns::parse(&request.dns.remote)
        .ok_or_else(|| format!("unknown remote DNS {:?}", request.dns.remote))?;
    let local_dns = LocalDns::parse(&request.dns.local)
        .ok_or_else(|| format!("unknown local DNS {:?}", request.dns.local))?;
    let anti_sanction_dns = zero_config::AntiSanctionDns::parse(&request.dns.anti_sanction)
        .ok_or_else(|| format!("unknown anti-sanction DNS {:?}", request.dns.anti_sanction))?;
    // A user-supplied anti-sanction resolver overrides the built-in one, with
    // the same rule as the remote tier: a bare IP or an IP-addressed
    // DoH/DoT/DoQ URL only, because a hostname cannot be bootstrapped on the
    // censored network.
    let custom_anti_sanction_dns = {
        let trimmed = request.dns.custom_anti_sanction.trim();
        if trimmed.is_empty() {
            None
        } else {
            match zero_config::dns::ResolverEndpoint::parse(trimmed) {
                Some(endpoint) if !endpoint.needs_bootstrap() => Some(trimmed.to_string()),
                _ => return Err(format!("unusable custom anti-sanction DNS {trimmed:?}")),
            }
        }
    };
    // A user-supplied resolver overrides the built-in remote tier. Validated
    // here so a resolver the runtime cannot parse is reported to the app
    // rather than failing the whole config at connect time. A resolver named
    // by hostname is rejected: the censored network cannot bootstrap its name,
    // so only a bare IP or an IP-addressed DoH/DoT/DoQ URL is usable.
    let custom_remote_dns = {
        let trimmed = request.dns.custom.trim();
        if trimmed.is_empty() {
            None
        } else {
            match zero_config::dns::ResolverEndpoint::parse(trimmed) {
                Some(endpoint) if !endpoint.needs_bootstrap() => Some(trimmed.to_string()),
                _ => return Err(format!("unusable custom DNS {trimmed:?}")),
            }
        }
    };
    // The same for the resolver of Iranian names, which is asked directly.
    let custom_local_dns = {
        let trimmed = request.dns.custom_local.trim();
        if trimmed.is_empty() {
            None
        } else {
            match zero_config::dns::ResolverEndpoint::parse(trimmed) {
                Some(endpoint) if !endpoint.needs_bootstrap() => Some(trimmed.to_string()),
                _ => return Err(format!("unusable custom local DNS {trimmed:?}")),
            }
        }
    };
    if !(576..=65_535).contains(&request.tun.mtu) {
        return Err("tun.mtu must be between 576 and 65535".into());
    }
    if request.socks_port == 0 || request.http_port == 0 || request.socks_port == request.http_port
    {
        return Err("socks_port and http_port must be distinct and non-zero".into());
    }

    // Links: validated one by one so the error names the culprit, then passed
    // in link form so the preset's parser is the only mapping from link to
    // outbound.
    // `auto` leaves an account in the order it was written with, which is the
    // order its servers were found and tested in.
    let warp_order = match request.warp_order.as_deref() {
        None | Some("") | Some("auto") => None,
        Some("server-first") => Some(zero_config::HybridMode::ServerFirst),
        Some("warp-first") => Some(zero_config::HybridMode::WarpFirst),
        Some(other) => {
            return Err(format!(
                "warp_order must be auto, server-first or warp-first, not {other:?}"
            ))
        }
    };
    let mut outbounds = Vec::with_capacity(request.links.len());
    // Where `geosite.dat`/`geoip.dat` and the cached domestic-SNI list live,
    // resolved once: the request's own path if it named one, else the host's.
    // Used below for the decoy names and later for managed geodata.
    let resolved_assets = request
        .assets_dir
        .clone()
        .or_else(|| assets_dir.map(Path::to_path_buf));
    // The extra decoy names the signed feed last cached there
    // (`domestic_feed`), kept as borrowed `&str` for the per-link pick. Empty
    // when the list has never been fetched, so the pick falls back to the
    // bundled pool — the offline floor.
    let domestic_names = resolved_assets
        .as_deref()
        .map(crate::domestic_feed::cached)
        .unwrap_or_default();
    let domestic_extra: Vec<&str> = domestic_names.iter().map(String::as_str).collect();
    for (index, link) in request.links.iter().enumerate() {
        let link = with_warp_order(link.trim(), warp_order);
        let parsed =
            zero_config::parse_link(&link).map_err(|error| format!("links[{index}]: {error}"))?;
        parsed
            .outbound
            .validate()
            .map_err(|error| format!("links[{index}]: {error}"))?;
        // A link describes the server, not this network, so evasion is layered
        // on rather than folded into it. Fragmentation skips ECH/plaintext and
        // REALITY (see `fragmentable`); SNI spoofing rides any TLS/REALITY
        // carrier (it adds a decoy packet without touching the real hello).
        //
        // Under `auto`, a link that already asks for ECH hides its own name,
        // which the splitting and decoy variants cannot be layered on. They are built
        // from the link without ECH instead (`"ech": false`), and the link as
        // written stays first: whichever of them gets through is kept.
        //
        // The same goes for a link that carries fragmentation of its own
        // (`fm=`, the setting its author found to work): it is tried as
        // written, and the other variants are built without it.
        let ech_written = evasion == Evasion::Auto
            && matches!(
                &parsed.outbound.stream.security,
                zero_config::Security::Tls(tls) if tls.ech.is_some()
            );
        let fm_written = evasion == Evasion::Auto
            && parsed.outbound.stream.evasion.tcp_fragment.is_some()
            && !matches!(
                parsed.outbound.protocol,
                zero_config::OutboundProtocol::Freedom { .. }
            );
        let written = ech_written || fm_written;
        let stripped;
        let shape = if written {
            let mut copy = parsed.outbound.clone();
            if let zero_config::Security::Tls(tls) = &mut copy.stream.security {
                tls.ech = None;
            }
            copy.stream.evasion.tcp_fragment = None;
            copy.stream.evasion.tcp_fragment_under = None;
            stripped = copy;
            &stripped
        } else {
            &parsed.outbound
        };
        let can_fragment = fragmentable(shape);
        // The decoy name for this server: one drawn from the allow-listed
        // pool and kept stable for the server, in place of the single
        // hard-coded host every link used to share (see
        // `zero_evasion::domestic`). The pool is the compiled-in names plus
        // whatever the signed feed last added (`domestic_extra`), so a name a
        // network starts throttling can be diluted without an app update.
        // Keyed on the server's own host, so it survives a subscription
        // refresh and so a throttled name only costs the servers that drew it,
        // not every link at once. Falls back to the one measured-good host for
        // an endpoint with no address to key on (never a spoofed carrier, so
        // it is academic).
        let decoy_sni = parsed
            .outbound
            .endpoint()
            .map(|(address, _)| {
                zero_evasion::domestic::pick_from(&address.host_string(), &domestic_extra)
            })
            .unwrap_or(SPOOF_DECOY_SNI);
        // The hop count rides along for a device without the MD5 option;
        // one with it never uses it (`zero_evasion::Fooling::Auto`).
        let spoof = (request.sni_spoof && sni_spoofable(shape)).then(|| {
            let mut spoof = json!({"fakeSni": decoy_sni});
            if request.decoy_ttl > 0 {
                spoof["ttl"] = json!(request.decoy_ttl);
            }
            spoof
        });
        // Compose one outbound's evasion object from an optional fragment length
        // and the optional SNI decoy; `None` when neither applies.
        let evasion_block = |length: Option<&str>| -> Option<Value> {
            let mut block = serde_json::Map::new();
            match length {
                Some(EMPTY_RECORD) => {
                    block.insert(
                        "fragment".into(),
                        json!({"packets": "tlshello", "lengths": ["0", "16384"], "delays": ["0"]}),
                    );
                }
                Some(length) => {
                    block.insert(
                        "fragment".into(),
                        json!({"packets": fragment_packets, "length": length, "interval": "1-1"}),
                    );
                }
                None => {}
            }
            if let Some(spoof) = &spoof {
                block.insert("sniSpoof".into(), spoof.clone());
            }
            (!block.is_empty()).then_some(Value::Object(block))
        };
        // One variant of this link: the link, what to layer on it, and the
        // ECH the link asked for dropped when that is what the layer needs.
        let variant = |evasion: Option<Value>| {
            let mut outbound = json!({"link": parsed.link});
            if let Some(evasion) = evasion {
                outbound["evasion"] = evasion;
            }
            if ech_written {
                outbound["ech"] = json!(false);
            }
            if fm_written {
                outbound["finalmask"] = Value::Null;
            }
            outbound
        };
        let push = |outbounds: &mut Vec<Value>, length: Option<&str>| {
            outbounds.push(variant(evasion_block(length)));
        };
        // Under `auto`, variants that hide the server name, for any link
        // with a name a filter can read, REALITY included: one with an
        // urgent byte in the name (free, works on any phone), and one behind
        // a decoy ClientHello where this device can send one (gets past more
        // filters, costs every connection a resend). They answer a filter
        // that puts the pieces of a split hello back together, and they come
        // last, so the balancer settles on them only when the others do not
        // get through. Left out when the user turned hiding on for every
        // variant.
        let hide_name = evasion == Evasion::Auto && spoof.is_none() && sni_spoofable(shape);
        let auto_urgent = hide_name && request.auto_decoy.unwrap_or_else(urgent_available);
        let auto_decoy = hide_name && request.auto_decoy.unwrap_or_else(decoy_available);
        // The TTL decoy, for a device that cannot send the MD5 one: its own
        // variant, so a hop count that is wrong for this network costs
        // nothing but a failed probe. Off with the decoy, or with no count.
        let auto_ttl_decoy = hide_name
            && request.decoy_ttl > 0
            && request.auto_decoy != Some(false)
            && request.auto_ttl_decoy.unwrap_or_else(ttl_decoy_available);
        // Fast Open too: free like the urgent byte, and it gets past a filter
        // the urgent byte does not (and the other way round). A TLS port only,
        // where the client speaks first.
        let auto_fast = hide_name
            && request.auto_fast_open.unwrap_or_else(fast_open_available)
            && parsed
                .outbound
                .endpoint()
                .is_some_and(|(_, port)| zero_net::fastopen::client_first_port(port));
        // The record version: free as well, needs nothing from the system, and
        // gets past a filter that only reads records of the usual versions.
        let auto_record = hide_name
            && request.auto_record.unwrap_or_else(record_available)
            && !zero_runtime::cdn_check::is_cloudflare_cdn(&parsed.outbound);
        let first = outbounds.len();
        if written {
            outbounds.push(json!({"link": parsed.link}));
        }
        match evasion {
            Evasion::Auto if can_fragment => {
                // Plain first, fragmented after — or the other way round when
                // other users here found fragmenting works better. The
                // balancer's probes then keep whichever gets through today.
                if !request.fragment_first {
                    push(&mut outbounds, None);
                }
                for length in AUTO_FRAGMENT_LENGTHS {
                    push(&mut outbounds, Some(length));
                }
                if request.fragment_first {
                    push(&mut outbounds, None);
                }
            }
            Evasion::Strong if can_fragment => push(&mut outbounds, Some("40-80")),
            // No fragmentation (Off, or a REALITY/QUIC link) — but the outbound
            // still carries the SNI decoy when spoofing is on.
            _ => push(&mut outbounds, None),
        }
        if auto_urgent {
            outbounds.push(variant(Some(json!({"sniSpoof": {"method": "urgent"}}))));
        }
        if auto_record {
            outbounds.push(variant(Some(json!({"sniSpoof": {"method": "record"}}))));
            // Not for REALITY or ShadowTLS, which drop a connection that
            // opens with an empty record.
            if crate::probe::empty_record_fits(&parsed.outbound) {
                outbounds.push(variant(Some(json!({"sniSpoof": {"method": "empty"}}))));
            }
        }
        if auto_fast {
            outbounds.push(variant(Some(json!({"sniSpoof": {"method": "fastopen"}}))));
        }
        if auto_decoy {
            outbounds.push(variant(Some(
                json!({"sniSpoof": {"fakeSni": decoy_sni, "method": "decoy"}}),
            )));
        }
        if auto_ttl_decoy {
            outbounds.push(variant(Some(json!({"sniSpoof": {
                "fakeSni": decoy_sni,
                "method": "decoy",
                "fooling": "ttl",
                "ttl": request.decoy_ttl,
            }}))));
        }
        // ECH last: it answers a filter that reads the name however the hello
        // is cut up, which is what a Cloudflare Worker's address meets.
        if evasion == Evasion::Auto && ech_variant_fits(&parsed.outbound) {
            let mut sealed = json!({"link": parsed.link, "ech": true});
            if fm_written {
                // A hello cannot be both encrypted and cut up.
                sealed["finalmask"] = Value::Null;
            }
            outbounds.push(sealed);
        }
        // The same link on other ports Cloudflare answers on: a network can
        // cut a name on 443 and leave it alone on 2053. Last, since most
        // links need none of them.
        if evasion == Evasion::Auto && alt_port_fits(&parsed.outbound) {
            for port in ALT_PORTS {
                let mut moved = variant(None);
                moved["port"] = json!(port);
                outbounds.push(moved);
            }
        }
        // Connection reuse, for a link that has an HTTP/2 connection to
        // reuse. Under `auto` with auto evasion every variant above keeps a
        // connection per request, and one more variant, a copy of the first
        // that reuses, goes right after it: on a network where reuse works it
        // answers the probes fastest and the balancer moves to it; where
        // something on the path cuts reused connections it fails them and is
        // left. Without auto evasion there are no variants to choose among,
        // so `auto` reuses, and the pool stops reusing for a server whose
        // reused connections stall.
        if reuses_connections(&parsed.outbound) {
            let tested = xmux == Xmux::Auto && evasion == Evasion::Auto;
            let reusing = tested.then(|| outbounds[first].clone());
            if xmux == Xmux::Off || tested {
                for outbound in &mut outbounds[first..] {
                    outbound["xmux"] = json!(false);
                }
            }
            if let Some(reusing) = reusing {
                outbounds.insert(first + 1, reusing);
            }
        }
        // Last, so it reaches every variant above, the connection-reusing
        // copy included. A carrier with no certificate TLS ignores it.
        if request.allow_insecure {
            for outbound in &mut outbounds[first..] {
                if outbound.get("link").is_some() {
                    outbound["allowInsecure"] = json!(true);
                }
            }
        }
    }
    // The balancer is keyed off how many proxy outbounds exist, not how many
    // links: one link under `auto` still expands into variants that need the
    // balancer to choose among.
    let proxy_count = outbounds.len();

    // Resolved once above for the decoy names; reused here for managed
    // geodata.
    let assets_dir = resolved_assets;
    let assets_present = assets_dir
        .as_ref()
        .is_some_and(|dir| dir.join("geosite.dat").is_file() && dir.join("geoip.dat").is_file());

    let lan_listen = request.lan.listen.trim();
    let listen = if request.lan.enabled {
        if lan_listen.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "lan.listen must be an IP address, got {lan_listen:?}"
            ));
        }
        lan_listen.to_string()
    } else {
        "127.0.0.1".to_string()
    };

    let preset = IranPreset {
        outbounds,
        listen: listen.clone(),
        socks_port: request.socks_port,
        http_port: Some(request.http_port),
        remote_dns,
        custom_remote_dns,
        local_dns,
        custom_local_dns,
        anti_sanction_dns,
        custom_anti_sanction_dns,
        block_ads: request.block_ads,
        // Applied per link above, where ECH can be skipped.
        fragment: false,
        // Given a directory, the rule sets always come from it. This used to
        // require the files to exist already, but nothing put them there, so
        // the assets block never appeared, nothing was ever downloaded and
        // every geosite:/geoip: rule (Iran-direct, ad blocking, private
        // ranges) was silently skipped.
        manage_assets: assets_dir.is_some(),
        asset_directory: assets_dir
            .as_ref()
            .map(|dir| dir.to_string_lossy().into_owned()),
        clean_ip_candidates: request
            .clean_ips
            .iter()
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect(),
        user_rules: request.routing_rules.clone(),
        ..IranPreset::default()
    };
    let mut config = preset.build();
    config["log"] = json!({"loglevel": request.log_level});
    // The app installs its own trimmed rule sets (a few tens of KB). With them
    // in place the core must not replace them with the full upstream lists:
    // geoip.dat alone is ~23 MB, fetched directly over a metered, filtered
    // network. Only when they are missing does it fall back to downloading.
    if config.get("assets").is_some() {
        config["assets"]["autoUpdate"] = json!(!assets_present);
    }

    // ---- inbounds
    let lan_auth = request.lan.enabled && !request.lan.user.is_empty();
    // LAN sharing without a password is an explicit choice the app made on
    // the user's behalf; the core's open-relay guard needs that consent in the
    // config when the ports move off loopback.
    let lan_open = request.lan.enabled && !lan_auth;
    let private = vpn && !request.lan.enabled && !request.local_auth.user.is_empty();
    if let Some(inbounds) = config["inbounds"].as_array_mut() {
        if private {
            inbounds.retain(|inbound| inbound["tag"] != "socks-in");
            for inbound in inbounds.iter_mut() {
                if inbound["tag"] == "http-in" {
                    inbound["listen"] = json!("127.0.0.1");
                    inbound["settings"] = json!({"accounts": [{
                        "user": request.local_auth.user,
                        "pass": request.local_auth.pass,
                    }]});
                }
            }
        }
        for inbound in inbounds.iter_mut() {
            match inbound["tag"].as_str() {
                Some("socks-in") if lan_auth => {
                    inbound["settings"] = json!({
                        "udp": true,
                        "auth": "password",
                        "accounts": [{"user": request.lan.user, "pass": request.lan.pass}],
                    });
                }
                // The HTTP inbound has no authentication in the runtime, so
                // when the user asked for a password it stays on loopback
                // rather than exposing an open proxy next to a protected one.
                Some("http-in") if lan_auth => {
                    inbound["listen"] = json!("127.0.0.1");
                }
                Some("socks-in") | Some("http-in") if lan_open => {
                    inbound["allowLanNoAuth"] = json!(true);
                }
                _ => {}
            }
        }
        if vpn {
            let mut addresses = vec![TUN_ADDRESS_V4];
            if request.tun.ipv6 {
                addresses.push(TUN_ADDRESS_V6);
            }
            inbounds.push(json!({
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "mtu": request.tun.mtu,
                    "addresses": addresses,
                    "tcp": true,
                    "udp": true,
                },
                "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]},
            }));
        }
    }

    // ---- outbounds: the preset's proxies come first (the first outbound is
    // the no-match default), then direct and block; `dns-out` joins the end.
    if vpn {
        if let Some(outbounds) = config["outbounds"].as_array_mut() {
            outbounds.push(json!({"tag": "dns-out", "protocol": "dns"}));
        }
    }

    // ---- routing
    let mut rules: Vec<Value> = config["routing"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !request.iran_direct {
        rules.retain(|rule| {
            let domestic_domains = rule.get("domain") == Some(&json!(IRAN_DIRECT_DOMAINS));
            let domestic_ips = rule.get("ip") == Some(&json!(IRAN_DIRECT_IPS));
            !(domestic_domains || domestic_ips)
        });
        // Private ranges stay local whatever the user chose: sending the LAN
        // to a foreign exit is never what "no split tunnelling" means.
        rules.push(json!({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}));
    }
    if vpn {
        rules.insert(
            0,
            json!({
                "type": "field",
                "inboundTag": ["tun-in"],
                "network": "udp",
                "port": 53,
                "outboundTag": "dns-out",
            }),
        );
    }
    if request.block_quic {
        // After the domestic rules, so QUIC to Iranian destinations still
        // goes direct; everything else falls back to TCP instead of timing
        // out on a path that cannot carry it well.
        rules.push(json!({
            "type": "field",
            "network": "udp",
            "port": 443,
            "outboundTag": "block",
        }));
    }
    let multi = proxy_count > 1;
    if multi {
        // A profile rule that says "through the tunnel" means whichever
        // server the balancer picked, not the first one.
        for rule in &mut rules {
            if rule.get("outboundTag") == Some(&json!("proxy")) {
                if let Some(rule) = rule.as_object_mut() {
                    rule.remove("outboundTag");
                    rule.insert("balancerTag".into(), json!("auto"));
                }
            }
        }
        rules.push(json!({
            "type": "field",
            "network": "tcp,udp",
            "balancerTag": "auto",
        }));
        config["routing"]["balancers"] = json!([{
            "tag": "auto",
            "selector": ["proxy"],
            "strategy": {"type": "leastPing"},
        }]);
        let mut observatory = config
            .get("observatory")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        observatory["probeUrl"] = json!(BALANCER_PROBE_URL);
        observatory["probeInterval"] = json!("60s");
        observatory["subjectSelector"] = json!(["proxy"]);
        config["observatory"] = observatory;
    }
    config["routing"]["rules"] = Value::Array(rules);

    // ---- DNS: FakeDNS answers the applications behind the TUN for every
    // name no domain-scoped tier claims (see the module documentation).
    if vpn && request.dns.fakedns {
        if let Some(servers) = config["dns"]["servers"].as_array_mut() {
            let catch_all = servers
                .iter()
                .position(|server| server.get("domains").is_none())
                .unwrap_or(servers.len());
            servers.insert(catch_all, json!({"address": "fakedns", "tag": "fakedns"}));
        }
    }

    // ---- DNS: without IPv6 in the tunnel, AAAA answers would only make
    // applications try a family that goes nowhere.
    if vpn && !request.tun.ipv6 {
        config["dns"]["queryStrategy"] = json!("UseIPv4");
    }

    zero_config::compile_config(&config, zero_core::GenerationId(1))
        .map_err(|error| error.to_string())?;
    Ok(config)
}

/// `link` with its WARP order replaced by `order`, when it is a WARP account
/// and an order is given; otherwise `link` as it is. Whether an exit carries
/// traffic first is kept, since only the order is being chosen here.
fn with_warp_order(
    link: &str,
    order: Option<zero_config::HybridMode>,
) -> std::borrow::Cow<'_, str> {
    let Some(order) = order else {
        return link.into();
    };
    let Some(summary) = crate::warp::summarize(link) else {
        return link.into();
    };
    if summary.hybrid == order {
        return link.into();
    }
    crate::warp::link_with_order(link, order, summary.prefer_exit).map_or(link.into(), Into::into)
}

/// Whether ClientHello fragmentation applies to this outbound.
/// Whether `auto` adds a variant that encrypts the server name with ECH: a
/// certificate-TLS link over a CDN transport that does not ask for ECH
/// itself and could be behind Cloudflare, which is the only CDN whose edge
/// takes the shared list. That is a known Cloudflare name or address, or any
/// domain (a Worker on its own domain is written that way), where a wrong
/// guess costs one more variant for the balancer to probe.
pub(crate) fn ech_variant_fits(outbound: &zero_config::Outbound) -> bool {
    use zero_config::{Security, Transport};
    let cdn_transport = matches!(
        outbound.stream.transport,
        Transport::WebSocket(_)
            | Transport::HttpUpgrade(_)
            | Transport::Grpc(_)
            | Transport::Xhttp(_)
    );
    matches!(&outbound.stream.security, Security::Tls(tls) if tls.ech.is_none())
        && cdn_transport
        && (zero_runtime::cdn_check::is_cloudflare_cdn(outbound)
            || matches!(
                outbound.endpoint(),
                Some((zero_core::Address::Domain(_), _))
            ))
}

/// Ports other than 443 that Cloudflare serves TLS on.
pub(crate) const ALT_PORTS: [u16; 2] = [2053, 8443];

/// Whether `auto` adds variants on [`ALT_PORTS`]: a link on 443 to a known
/// Cloudflare name or address over a CDN transport with certificate TLS.
pub(crate) fn alt_port_fits(outbound: &zero_config::Outbound) -> bool {
    outbound.endpoint().is_some_and(|(_, port)| port == 443)
        && zero_runtime::cdn_check::is_cloudflare_cdn(outbound)
}

fn fragmentable(outbound: &zero_config::Outbound) -> bool {
    // QUIC carriers (Hysteria2/TUIC) run over UDP: there is no TCP ClientHello
    // to split, and the model forbids layering TCP-shaped evasion on them. They
    // manage their own QUIC handshake, so leave them untouched.
    if matches!(
        outbound.protocol,
        zero_config::OutboundProtocol::Hysteria2(_)
            | zero_config::OutboundProtocol::Tuic(_)
            | zero_config::OutboundProtocol::Juicity(_)
    ) {
        return false;
    }
    match &outbound.stream.security {
        zero_config::Security::None => false,
        zero_config::Security::Tls(tls) => tls.ech.is_none(),
        // REALITY already names a real, unblocked SNI, so a fragment hides
        // nothing — and REALITY servers reject a ClientHello split across TLS
        // records: they read the first record expecting a whole hello, miss
        // the auth tag, and relay to the decoy (real Xray with `tlshello`
        // fails the same way), so fragmenting a REALITY link breaks the tunnel
        // outright. Left whole, matching the TUI's `outbound_shreds_well`.
        zero_config::Security::Reality(_) => false,
        // Splitting the ShadowTLS ClientHello across TLS records would break
        // the relay's frame extraction and the data-stream HMAC the same way
        // it breaks REALITY, so the hello is left whole.
        zero_config::Security::ShadowTls(_) => false,
    }
}

/// The decoy SNI stamped into a spoofed ClientHello: a widely-allow-listed
/// name, so a DPI parser sees an unblocked destination. The real hello (and
/// its true SNI) still reaches the server untouched.
///
/// A speed test host, the same one the REALITY masker, the clean-IP scanner
/// and the HTTP/2 SNI default all use: it resolves on many networks, nobody
/// throttles it, and a censor that probes it finds a real site.
pub(crate) const SPOOF_DECOY_SNI: &str = "www.speedtest.net";

/// Whether this device can send a decoy ClientHello at all. Unit tests get a
/// fixed "no", so what they build does not depend on the kernel they run on;
/// the ones about the decoy ask for it with `auto_decoy`.
fn decoy_available() -> bool {
    !cfg!(test) && zero_evasion::decoy::available()
}

/// Whether the TTL decoy is worth a variant here: the device has name hiding
/// on, can set a hop limit and has no MD5 option. A fixed "no" in tests.
fn ttl_decoy_available() -> bool {
    !cfg!(test) && zero_evasion::decoy::ttl_available()
}

/// Whether `outbound` runs over an HTTP/2 connection that XMUX can reuse:
/// XHTTP over HTTP/2, in any mode.
fn reuses_connections(outbound: &zero_config::Outbound) -> bool {
    matches!(
        &outbound.stream.transport,
        zero_config::Transport::Xhttp(xhttp)
            if xhttp.xhttp_http_version == zero_config::XhttpHttpVersion::Http2
    )
}

/// Whether this device can put a hello in the SYN. A fixed "no" in tests.
fn fast_open_available() -> bool {
    !cfg!(test) && zero_net::fastopen::supported()
}

/// Whether the record-version variant is worth adding: name hiding is on.
/// It needs nothing else from the device. A fixed "no" in tests.
fn record_available() -> bool {
    !cfg!(test) && zero_evasion::decoy::enabled()
}

/// The same question for the urgent byte, with the same fixed "no" in tests.
fn urgent_available() -> bool {
    !cfg!(test) && zero_evasion::decoy::enabled() && zero_evasion::urgent::supported()
}

/// Whether raw fake-SNI injection applies to this outbound. Unlike
/// fragmentation it adds a *separate* decoy packet and never touches the real
/// ClientHello, so REALITY is fine — but there must be a TCP TLS/REALITY hello
/// to hide behind, so plaintext, ECH and QUIC carriers are skipped.
pub(crate) fn sni_spoofable(outbound: &zero_config::Outbound) -> bool {
    if matches!(
        outbound.protocol,
        zero_config::OutboundProtocol::Hysteria2(_)
            | zero_config::OutboundProtocol::Tuic(_)
            | zero_config::OutboundProtocol::Juicity(_)
    ) {
        return false;
    }
    match &outbound.stream.security {
        zero_config::Security::None => false,
        zero_config::Security::Tls(tls) => tls.ech.is_none(),
        zero_config::Security::Reality(_) => true,
        // ShadowTLS already sends a genuine decoy SNI, and the model refuses
        // any TCP evasion under it (`Outbound::validate`), so a spoof added
        // here would only make the whole config fail to compile.
        zero_config::Security::ShadowTls(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::tests::{HYSTERIA2, REALITY, SS, TROJAN, WS_TLS};

    fn compile(config: &Value) -> std::sync::Arc<zero_config::RuntimeConfig> {
        let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
            .unwrap_or_else(|error| panic!("{error}\n{config:#}"));
        generation.config
    }

    /// In VPN mode with a password from the host, no other app on the device
    /// can use the local ports: the SOCKS one is gone and the HTTP one asks
    /// for the password.
    #[test]
    fn a_local_password_closes_the_loopback_proxy_to_other_apps() {
        let config = build_config(&json!({
            "links": [SS], "mode": "vpn",
            "local_auth": {"user": "u1", "pass": "p1"}
        }))
        .unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().all(|i| i["tag"] != "socks-in"));
        let http = inbounds.iter().find(|i| i["tag"] == "http-in").unwrap();
        assert_eq!(http["listen"], "127.0.0.1");
        assert_eq!(http["settings"]["accounts"][0]["user"], "u1");
        assert!(inbounds.iter().any(|i| i["tag"] == "tun-in"));
        // And the runtime reads it as an inbound that asks for the password.
        let compiled = compile(&config);
        let http = compiled
            .inbounds
            .iter()
            .find(|i| i.tag.as_ref() == "http-in")
            .unwrap();
        assert!(matches!(
            &http.socks_auth,
            zero_config::SocksAuth::Password(accounts) if accounts.len() == 1
        ));
    }

    /// The password is for VPN mode only. In proxy mode, and when the user
    /// shares the connection on the LAN, the ports are for others to use.
    #[test]
    fn a_local_password_leaves_proxy_mode_and_lan_sharing_alone() {
        for request in [
            json!({"links": [SS], "mode": "proxy", "local_auth": {"user": "u", "pass": "p"}}),
            json!({"links": [SS], "mode": "vpn", "lan": {"enabled": true},
                   "local_auth": {"user": "u", "pass": "p"}}),
            json!({"links": [SS], "mode": "vpn"}),
        ] {
            let config = build_config(&request).unwrap();
            let inbounds = config["inbounds"].as_array().unwrap();
            assert!(inbounds.iter().any(|i| i["tag"] == "socks-in"), "{request}");
            let http = inbounds.iter().find(|i| i["tag"] == "http-in").unwrap();
            assert!(http["settings"]["accounts"].is_null(), "{request}");
        }
    }

    #[test]
    fn a_vpn_config_has_a_tun_inbound_and_dns_hijack() {
        let config = build_config(&json!({"links": [REALITY]})).unwrap();
        let compiled = compile(&config);
        let tun = compiled
            .inbounds
            .iter()
            .find(|inbound| inbound.tag.as_ref() == "tun-in")
            .expect("tun inbound");
        let zero_config::InboundProtocol::Tun(settings) = &tun.protocol else {
            panic!("tun-in is not a TUN inbound");
        };
        assert_eq!(settings.mtu, 1500);
        assert_eq!(settings.addresses.as_ref(), [Box::from(TUN_ADDRESS_V4)]);
        assert!(tun.sniffing.enabled);

        assert!(compiled
            .outbounds
            .iter()
            .any(|outbound| outbound.tag.as_ref() == "dns-out"
                && matches!(outbound.protocol, zero_config::OutboundProtocol::Dns { .. })));
        let first = &compiled.routing.rules[0];
        assert!(
            matches!(&first.target, zero_config::routing::RuleTarget::Outbound(tag) if tag.as_ref() == "dns-out")
        );
        assert_eq!(first.inbound_tags, vec![Box::<str>::from("tun-in")]);
        // The first outbound is the no-match default and must be the proxy.
        assert_eq!(compiled.outbounds[0].tag.as_ref(), "proxy");
        assert_eq!(
            compiled.dns.query_strategy,
            zero_config::dns::QueryStrategy::UseIpv4
        );
        // QUIC is blocked by default.
        assert!(config["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["port"] == 443 && rule["outboundTag"] == "block"));
    }

    #[test]
    fn ipv6_adds_the_v6_address_and_keeps_both_families() {
        let config = build_config(&json!({
            "links": [REALITY], "tun": {"mtu": 9000, "ipv6": true}
        }))
        .unwrap();
        let compiled = compile(&config);
        let tun = compiled
            .inbounds
            .iter()
            .find(|i| i.tag.as_ref() == "tun-in")
            .unwrap();
        let zero_config::InboundProtocol::Tun(settings) = &tun.protocol else {
            panic!()
        };
        assert_eq!(settings.mtu, 9000);
        assert_eq!(settings.addresses.len(), 2);
        assert_eq!(
            compiled.dns.query_strategy,
            zero_config::dns::QueryStrategy::UseIp
        );
    }

    #[test]
    fn a_custom_remote_dns_overrides_the_encrypted_tier() {
        let config = build_config(&json!({
            "links": [REALITY], "dns": {"remote": "google", "custom": "9.9.9.9"}
        }))
        .unwrap();
        let compiled = compile(&config);
        let remote = compiled
            .dns
            .servers
            .iter()
            .find(|server| server.tag.as_deref() == Some("remote"))
            .expect("the encrypted tier must exist");
        assert!(matches!(
            &remote.endpoint,
            zero_config::dns::ResolverEndpoint::Udp { address, .. } if address.is_ip()
        ));
    }

    #[test]
    fn the_anti_sanction_resolver_is_selectable_and_overridable() {
        // A built-in name selects that resolver's addresses for the tag.
        let config = build_config(&json!({
            "links": [REALITY], "dns": {"anti_sanction": "electro"}
        }))
        .unwrap();
        let servers = config["dns"]["servers"].as_array().unwrap();
        assert!(servers
            .iter()
            .any(|s| s["tag"] == "anti-sanction" && s["address"] == "78.157.42.100"));

        // A usable custom resolver replaces the built-in addresses.
        let config = build_config(&json!({
            "links": [REALITY], "dns": {"anti_sanction": "shecan", "custom_anti_sanction": "10.202.10.10"}
        }))
        .unwrap();
        let servers = config["dns"]["servers"].as_array().unwrap();
        let anti: Vec<&str> = servers
            .iter()
            .filter(|s| s["tag"] == "anti-sanction")
            .filter_map(|s| s["address"].as_str())
            .collect();
        assert_eq!(anti, ["10.202.10.10"]);
        compile(&config);

        // "none" removes the third verdict entirely.
        let config = build_config(&json!({
            "links": [REALITY], "dns": {"anti_sanction": "none"}
        }))
        .unwrap();
        assert!(!config["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["tag"] == "anti-sanction"));

        // Unknown names and un-bootstrappable custom resolvers are errors.
        assert!(build_config(&json!({
            "links": [REALITY], "dns": {"anti_sanction": "nowhere"}
        }))
        .unwrap_err()
        .contains("anti-sanction"));
        assert!(build_config(&json!({
            "links": [REALITY], "dns": {"custom_anti_sanction": "resolver.example.com"}
        }))
        .unwrap_err()
        .contains("anti-sanction"));
    }

    #[test]
    fn a_custom_local_dns_replaces_the_resolver_of_iranian_names() {
        let servers = |dns: Value| -> Vec<Value> {
            let config = build_config(&json!({"links": [REALITY], "dns": dns})).unwrap();
            config["dns"]["servers"].as_array().unwrap().clone()
        };
        let local_address = |servers: &[Value]| {
            servers
                .iter()
                .find(|s| s["tag"] == "local")
                .map(|s| s["address"].clone())
        };
        assert_eq!(local_address(&servers(json!({}))), Some(json!("8.8.8.8")));
        assert_eq!(
            local_address(&servers(json!({"local": "cloudflare"}))),
            Some(json!("1.1.1.1"))
        );
        assert_eq!(
            local_address(&servers(json!({"custom_local": "178.22.122.100"}))),
            Some(json!("178.22.122.100"))
        );
        // Blank means none; one that could not be used is said so.
        assert_eq!(
            local_address(&servers(json!({"custom_local": "  "}))),
            Some(json!("8.8.8.8"))
        );
        let error = build_config(&json!({
            "links": [REALITY], "dns": {"custom_local": "resolver.example.com"}
        }))
        .unwrap_err();
        assert!(error.contains("custom local DNS"), "{error}");
    }

    #[test]
    fn an_unparseable_custom_remote_dns_is_an_error() {
        let error = build_config(&json!({
            "links": [REALITY], "dns": {"remote": "google", "custom": "not a resolver!!"}
        }))
        .unwrap_err();
        assert!(error.contains("custom DNS"), "{error}");
    }

    #[test]
    fn fakedns_answers_applications_but_not_domain_scoped_tiers() {
        let config = build_config(&json!({"links": [REALITY], "dns": {"fakedns": true}})).unwrap();
        let servers = config["dns"]["servers"].as_array().unwrap();
        let fake = servers
            .iter()
            .position(|s| s["address"] == "fakedns")
            .expect("fakedns server");
        // Every domain-scoped tier comes first, the catch-all remote after it.
        assert!(servers[..fake].iter().all(|s| s.get("domains").is_some()));
        assert!(servers[fake + 1..]
            .iter()
            .any(|s| s.get("domains").is_none()));
        let compiled = compile(&config);
        assert!(compiled
            .dns
            .servers
            .iter()
            .any(|s| s.endpoint == zero_config::dns::ResolverEndpoint::FakeDns));

        // Off, and in proxy mode (no TUN, no applications to answer): absent.
        for request in [
            json!({"links": [REALITY], "dns": {"fakedns": false}}),
            json!({"links": [REALITY], "mode": "proxy", "dns": {"fakedns": true}}),
        ] {
            let config = build_config(&request).unwrap();
            assert!(!config["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["address"] == "fakedns"));
        }
    }

    #[test]
    fn a_proxy_config_has_no_tun_and_no_dns_outbound() {
        let config = build_config(&json!({"links": [WS_TLS], "mode": "proxy"})).unwrap();
        let compiled = compile(&config);
        assert_eq!(compiled.inbounds.len(), 2);
        assert!(compiled
            .inbounds
            .iter()
            .all(|inbound| inbound.listen.host_string() == "127.0.0.1"));
        assert!(!compiled.outbounds.iter().any(|outbound| matches!(
            outbound.protocol,
            zero_config::OutboundProtocol::Dns { .. }
        )));
    }

    #[test]
    fn lan_sharing_binds_the_lan_and_protects_what_it_can() {
        let open = build_config(&json!({
            "links": [SS], "mode": "proxy", "lan": {"enabled": true, "listen": "0.0.0.0"}
        }))
        .unwrap();
        let compiled = compile(&open);
        assert!(compiled
            .inbounds
            .iter()
            .all(|inbound| inbound.listen.host_string() == "0.0.0.0"));

        let protected = build_config(&json!({
            "links": [SS], "mode": "proxy",
            "lan": {"enabled": true, "listen": "0.0.0.0", "user": "u", "pass": "p"}
        }))
        .unwrap();
        let compiled = compile(&protected);
        let socks = compiled
            .inbounds
            .iter()
            .find(|i| i.tag.as_ref() == "socks-in")
            .unwrap();
        assert_eq!(socks.listen.host_string(), "0.0.0.0");
        assert!(matches!(
            socks.socks_auth,
            zero_config::SocksAuth::Password(_)
        ));
        let http = compiled
            .inbounds
            .iter()
            .find(|i| i.tag.as_ref() == "http-in")
            .unwrap();
        assert_eq!(http.listen.host_string(), "127.0.0.1");
    }

    #[test]
    fn several_links_get_a_least_ping_balancer_and_the_observatory() {
        let config = build_config(&json!({
            "links": [REALITY, WS_TLS, TROJAN], "evasion": "strong"
        }))
        .unwrap();
        let compiled = compile(&config);
        let tags: Vec<&str> = compiled.outbounds.iter().map(|o| o.tag.as_ref()).collect();
        assert_eq!(&tags[..3], ["proxy", "proxy-1", "proxy-2"]);
        let balancer = &compiled.routing.balancers[0];
        assert_eq!(balancer.tag.as_ref(), "auto");
        assert_eq!(
            balancer.strategy,
            zero_config::routing::BalancerStrategy::LeastPing
        );
        assert_eq!(compiled.expand_balancer(balancer).len(), 3);
        let last = compiled.routing.rules.last().unwrap();
        assert!(
            matches!(&last.target, zero_config::routing::RuleTarget::Balancer(tag) if tag.as_ref() == "auto")
        );
        let observatory = compiled.observatory.as_ref().unwrap();
        assert_eq!(
            observatory.probe_interval,
            std::time::Duration::from_secs(60)
        );
        // Strong evasion fragments every TLS link, but never REALITY: its
        // ClientHello must reach the server whole. proxy = REALITY here.
        assert!(
            compiled.outbounds[0].stream.evasion.tcp_fragment.is_none(),
            "REALITY was fragmented: {}",
            compiled.outbounds[0].tag
        );
        for outbound in &compiled.outbounds[1..3] {
            assert!(
                outbound.stream.evasion.tcp_fragment.is_some(),
                "{}",
                outbound.tag
            );
        }
    }

    /// The fragment lengths of the proxy outbounds in `config`, in order;
    /// `None` for a plain one and `"empty"` for the empty-record one.
    fn variant_lengths(config: &Value) -> Vec<Option<String>> {
        config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| {
                o["tag"]
                    .as_str()
                    .is_some_and(|t| t == "proxy" || t.starts_with("proxy-"))
                    && o["ech"] != true
            })
            .map(|o| {
                let fragment = &o["evasion"]["fragment"];
                if fragment["lengths"][0] == "0" {
                    return Some(EMPTY_RECORD.to_string());
                }
                fragment["length"].as_str().map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn auto_tries_the_link_plain_first_then_fragmented() {
        let config = build_config(&json!({"links": [WS_TLS], "evasion": "auto"})).unwrap();
        assert_eq!(
            variant_lengths(&config),
            [None, Some("empty".into()), Some("40-80".into())]
        );
        let compiled = compile(&config);
        // One link still gets the balancer that chooses among its variants.
        assert_eq!(compiled.routing.balancers.len(), 1);
        assert_eq!(
            compiled
                .expand_balancer(&compiled.routing.balancers[0])
                .len(),
            // Plain, the two shaped ones, and the ECH one.
            4
        );
        // The shaped variants: an empty record ahead of the hello, then the
        // hello as TCP segments.
        let fragments: Vec<_> = compiled
            .outbounds
            .iter()
            .filter_map(|o| o.stream.evasion.tcp_fragment.as_ref())
            .collect();
        assert_eq!(fragments.len(), 2);
        assert_eq!(*fragments[0], zero_config::FragmentConfig::empty_record());
        assert_eq!(
            fragments[1].packets,
            zero_config::FragmentPackets::Range { from: 1, to: 1 }
        );
    }

    /// The ECH settings of each proxy outbound of `config`, in order:
    /// `None` without ECH, else whether the list is still to be looked up.
    fn ech_of(config: &Value) -> Vec<Option<bool>> {
        compile(config)
            .outbounds
            .iter()
            .filter(|o| o.tag.as_ref() == "proxy" || o.tag.starts_with("proxy-"))
            .map(|o| match &o.stream.security {
                zero_config::Security::Tls(tls) => {
                    tls.ech.as_ref().map(|ech| ech.config_list.is_empty())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn auto_ends_a_cdn_links_variants_with_one_that_encrypts_its_name() {
        let config = build_config(&json!({
            "links": [WS_TLS], "evasion": "auto", "auto_decoy": false
        }))
        .unwrap();
        // Plain, the two shaped ones, then ECH.
        assert_eq!(ech_of(&config), [None, None, None, Some(true)]);
        // Not asked for, not added: a fixed mode has no variants, and a
        // REALITY or plain TCP link has no CDN to hide behind.
        let off = build_config(&json!({"links": [WS_TLS], "evasion": "off"})).unwrap();
        assert_eq!(ech_of(&off), [None]);
        let reality = build_config(&json!({"links": [REALITY], "evasion": "auto"})).unwrap();
        assert!(ech_of(&reality).iter().all(Option::is_none));
        let trojan = build_config(&json!({"links": [TROJAN], "evasion": "auto"})).unwrap();
        assert!(ech_of(&trojan).iter().all(Option::is_none));
    }

    #[test]
    fn a_link_that_asks_for_ech_stays_first_and_gets_unhidden_variants_too() {
        // Xray's own spelling of "look the list up", as feeds write it.
        let link = WS_TLS.replace(
            "&encryption=none",
            "&encryption=none&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1",
        );
        let config = build_config(&json!({
            "links": [link], "evasion": "auto", "auto_decoy": false
        }))
        .unwrap();
        // As written, then plain, the empty record and the segments without
        // ECH (it cannot be split), and no second ECH variant.
        assert_eq!(ech_of(&config), [Some(true), None, None, None]);
        let compiled = compile(&config);
        let written = compiled
            .outbounds
            .iter()
            .find(|o| o.tag.as_ref() == "proxy");
        let Some(zero_config::Security::Tls(tls)) = written.map(|o| &o.stream.security) else {
            panic!("first outbound is not TLS");
        };
        let ech = tls.ech.as_ref().expect("the link's ECH is kept");
        assert_eq!(ech.query_name.as_deref(), Some("cloudflare-ech.com"));
        // With fragmentation forced on, the link is left as written.
        let strong = build_config(&json!({"links": [link], "evasion": "strong"})).unwrap();
        assert_eq!(ech_of(&strong), [Some(true)]);
    }

    /// The fragment length of each proxy outbound of the compiled `config`,
    /// `None` where it is not fragmented.
    fn fragment_lengths(config: &Value) -> Vec<Option<(u32, u32)>> {
        compile(config)
            .outbounds
            .iter()
            .filter(|o| o.tag.as_ref() == "proxy" || o.tag.starts_with("proxy-"))
            .map(|o| {
                o.stream
                    .evasion
                    .tcp_fragment
                    .as_ref()
                    .map(|f| (f.length.min, f.length.max))
            })
            .collect()
    }

    const FM: &str = "%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%2210-20%22%2C%22delay%22%3A%221-1%22%7D%7D%5D%7D";

    #[test]
    fn a_link_with_its_own_fragmentation_is_tried_as_written_then_without() {
        let link = WS_TLS.replace("&encryption=none", &format!("&encryption=none&fm={FM}"));
        let config = build_config(&json!({
            "links": [link], "evasion": "auto", "auto_decoy": false
        }))
        .unwrap();
        // As written; plain; the two shaped ones (an empty record, whose
        // piece is the rest of the hello, then 40-80); ECH, which cannot be cut.
        assert_eq!(
            fragment_lengths(&config),
            [
                Some((10, 20)),
                None,
                Some((16384, 16384)),
                Some((40, 80)),
                None
            ]
        );
        // A fixed mode keeps the link's own and adds nothing.
        let off = build_config(&json!({"links": [link], "evasion": "off"})).unwrap();
        assert_eq!(fragment_lengths(&off), [Some((10, 20))]);
    }

    #[test]
    fn a_direct_profile_builds_one_fragmenting_outbound_and_nothing_else() {
        let link = format!("direct://?fm={FM}#Serverless");
        for mode in ["auto", "off", "strong"] {
            let config = build_config(&json!({"links": [link], "evasion": mode})).unwrap();
            assert_eq!(fragment_lengths(&config), [Some((10, 20))], "{mode}");
            let compiled = compile(&config);
            assert!(matches!(
                compiled.outbounds[0].protocol,
                zero_config::OutboundProtocol::Freedom { .. }
            ));
        }
    }

    #[test]
    fn ech_fits_only_cdn_links_that_could_be_behind_cloudflare() {
        let fits = |link: &str| ech_variant_fits(&zero_config::parse_link(link).unwrap().outbound);
        assert!(fits(WS_TLS));
        // A Cloudflare address, written as an address.
        assert!(fits(
            &WS_TLS.replace("cdn.example.com:443", "104.16.10.2:443")
        ));
        // An address that is not Cloudflare's has no shared list to use.
        assert!(!fits(
            &WS_TLS.replace("cdn.example.com:443", "203.0.113.5:443")
        ));
        // Nothing to encrypt, or nothing to hide behind a CDN.
        assert!(!fits(REALITY));
        assert!(!fits(TROJAN));
        // Already asks for it.
        assert!(!fits(
            &WS_TLS.replace("#NL-edge", "&ech=udp%3A%2F%2F1.1.1.1#NL-edge")
        ));
    }

    #[test]
    fn auto_starts_fragmented_when_others_here_found_that_works() {
        let config = build_config(&json!({
            "links": [WS_TLS], "evasion": "auto", "fragment_first": true
        }))
        .unwrap();
        assert_eq!(
            variant_lengths(&config),
            [Some("empty".into()), Some("40-80".into()), None]
        );
        compile(&config);
    }

    #[test]
    fn smart_is_now_auto() {
        let smart = build_config(&json!({"links": [WS_TLS], "evasion": "smart"})).unwrap();
        let auto = build_config(&json!({"links": [WS_TLS], "evasion": "auto"})).unwrap();
        assert_eq!(variant_lengths(&smart), variant_lengths(&auto));
    }

    #[test]
    fn the_one_one_packets_fallback_reaches_every_fragment() {
        // BPB's fallback: when tlshello fragmentation stops getting through,
        // switch the write mode to a `1-1` range. It must apply to each swept
        // variant, not just the first.
        let config = build_config(&json!({
            "links": [WS_TLS], "evasion": "auto", "fragment_packets": "1-1"
        }))
        .unwrap();
        let modes: Vec<&str> = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["evasion"]["fragment"]["packets"].as_str())
            .collect();
        // The empty-record variant is always `tlshello`: an empty record is
        // TLS framing, whatever the split variants are set to.
        assert_eq!(modes, ["tlshello", "1-1"]);
        compile(&config);

        // A nonsense packets value is rejected by name.
        assert!(build_config(&json!({
            "links": [WS_TLS], "evasion": "strong", "fragment_packets": "nonsense"
        }))
        .unwrap_err()
        .contains("fragment_packets"));
    }

    #[test]
    fn reality_links_are_never_fragmented() {
        // Fragmenting a REALITY ClientHello breaks it: the server reads the
        // first record expecting a whole hello, misses the auth tag and relays
        // to the decoy. So under either evasion mode a REALITY link stays one
        // plain outbound, unfragmented, with no length sweep and no balancer.
        for mode in ["strong", "auto"] {
            let config = build_config(&json!({
                "links": [REALITY], "evasion": mode
            }))
            .unwrap();
            let proxies = config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o["tag"].as_str().is_some_and(|t| t.starts_with("proxy")))
                .count();
            assert_eq!(proxies, 1, "mode {mode}: REALITY was expanded/fragmented");
            let compiled = compile(&config);
            assert!(
                compiled.outbounds[0].stream.evasion.tcp_fragment.is_none(),
                "mode {mode}: REALITY was fragmented"
            );
            assert!(
                compiled.routing.balancers.is_empty(),
                "mode {mode}: a single REALITY link should need no balancer"
            );
        }
    }

    #[test]
    fn sni_spoof_rides_reality_without_fragmenting_it() {
        // SNI spoofing adds a decoy packet, it does not split the hello, so it
        // is safe on REALITY: the link stays one unfragmented outbound that
        // now also carries the fake-SNI desync.
        let config =
            build_config(&json!({"links": [REALITY], "evasion": "auto", "sni_spoof": true}))
                .unwrap();
        let compiled = compile(&config);
        let ev = &compiled.outbounds[0].stream.evasion;
        assert!(ev.sni_desync.is_some(), "REALITY did not get the SNI decoy");
        assert!(ev.tcp_fragment.is_none(), "REALITY must not be fragmented");
    }

    #[test]
    fn sni_spoof_and_fragmentation_combine_on_a_tls_link() {
        let config =
            build_config(&json!({"links": [WS_TLS], "evasion": "strong", "sni_spoof": true}))
                .unwrap();
        let compiled = compile(&config);
        let ev = &compiled.outbounds[0].stream.evasion;
        assert!(ev.tcp_fragment.is_some(), "fragment lost");
        assert!(ev.sni_desync.is_some(), "SNI decoy lost");
    }

    /// `auto` on a device that can send a decoy: every link with a readable
    /// name gets one more variant behind it, REALITY too, after the others.
    /// On a device without the MD5 option the TTL decoy is a variant of its
    /// own, with the user's hop count, and never on top of the switches that
    /// turn it off.
    #[test]
    fn auto_adds_a_ttl_decoy_variant_where_asked() {
        let spoofs = |request: Value| -> Vec<zero_config::SniDesyncConfig> {
            compile(&build_config(&request).unwrap())
                .outbounds
                .iter()
                .filter_map(|o| o.stream.evasion.sni_desync.clone())
                .collect()
        };
        let ttl = spoofs(json!({
            "links": [REALITY], "evasion": "auto", "auto_ttl_decoy": true, "decoy_ttl": 6,
        }));
        let last = ttl.last().expect("a TTL decoy variant");
        assert_eq!(last.method, zero_config::SniMethod::Decoy);
        assert_eq!(last.fooling, zero_config::DecoyFooling::Ttl);
        assert_eq!(last.ttl, 6);
        let no_ttl = |request: Value| {
            !spoofs(request)
                .iter()
                .any(|spoof| spoof.fooling == zero_config::DecoyFooling::Ttl)
        };
        assert!(no_ttl(json!({
            "links": [REALITY], "evasion": "auto", "auto_ttl_decoy": true, "decoy_ttl": 0,
        })));
        assert!(no_ttl(json!({
            "links": [REALITY], "evasion": "auto", "auto_ttl_decoy": true, "auto_decoy": false,
        })));
        assert!(no_ttl(json!({"links": [REALITY], "evasion": "auto"})));
        // The user's own switch carries the hop count for a device that
        // needs it, and leaves the MD5 option first where there is one.
        let always = spoofs(json!({"links": [REALITY], "sni_spoof": true, "decoy_ttl": 5}));
        assert_eq!(always.len(), 1);
        assert_eq!(always[0].fooling, zero_config::DecoyFooling::Auto);
        assert_eq!(always[0].ttl, 5);
    }

    /// XHTTP over HTTP/2: `auto` keeps every variant on a connection of its
    /// own and adds one that reuses, right after the first; `off` and `on`
    /// add nothing and say the same for every variant.
    #[test]
    fn xmux_auto_adds_a_reusing_variant_for_xhttp_over_http2() {
        let reuse = |request: Value| -> Vec<bool> {
            compile(&build_config(&request).unwrap())
                .outbounds
                .iter()
                .filter_map(|o| match &o.stream.transport {
                    zero_config::Transport::Xhttp(x) => Some(x.xhttp.xmux.reuses()),
                    _ => None,
                })
                .collect()
        };
        let link = crate::link::tests::XHTTP_EXTRA;
        let auto = reuse(json!({"links": [link], "evasion": "auto"}));
        assert!(auto.len() >= 3, "{auto:?}");
        assert_eq!(auto[..2], [false, true]);
        assert_eq!(auto.iter().filter(|reuses| **reuses).count(), 1);
        let off = reuse(json!({"links": [link], "evasion": "auto", "xmux": "off"}));
        assert_eq!(off.len(), auto.len() - 1);
        assert!(off.iter().all(|reuses| !reuses));
        let on = reuse(json!({"links": [link], "evasion": "auto", "xmux": "on"}));
        assert!(on.iter().all(|reuses| *reuses));
        // Without auto's variants there is nothing to choose among, so
        // `auto` reuses (the pool watches it); `off` still means off.
        assert_eq!(reuse(json!({"links": [link], "evasion": "off"})), [true]);
        assert_eq!(
            reuse(json!({"links": [link], "evasion": "off", "xmux": "off"})),
            [false]
        );
        // Another transport is left alone, and a bad value is named.
        assert!(reuse(json!({"links": [REALITY], "evasion": "auto"})).is_empty());
        assert!(build_config(&json!({"links": [link], "xmux": "sometimes"})).is_err());
    }

    #[test]
    fn auto_adds_a_decoy_variant_where_the_device_can_send_one() {
        let decoys = |request: Value| -> Vec<bool> {
            compile(&build_config(&request).unwrap())
                .outbounds
                .iter()
                .filter(|o| !matches!(o.stream.security, zero_config::Security::None))
                .map(|o| o.stream.evasion.sni_desync.is_some())
                .collect()
        };
        assert_eq!(
            decoys(json!({"links": [REALITY], "evasion": "auto", "auto_decoy": true})),
            [false, true, true]
        );
        let tls = decoys(json!({"links": [WS_TLS], "evasion": "auto", "auto_decoy": true}));
        // The decoys, then the ECH variant, which hides its name by itself.
        assert_eq!(tls[tls.len() - 3..], [true, true, false]);
        assert_eq!(tls.iter().filter(|decoy| **decoy).count(), 2);
        // The urgent byte first, then the decoy.
        let methods: Vec<_> = compile(
            &build_config(&json!({"links": [REALITY], "evasion": "auto", "auto_decoy": true}))
                .unwrap(),
        )
        .outbounds
        .iter()
        .filter_map(|o| o.stream.evasion.sni_desync.as_ref().map(|d| d.method))
        .collect();
        assert_eq!(
            methods,
            [
                zero_config::SniMethod::Urgent,
                zero_config::SniMethod::Decoy
            ]
        );
        // Fast Open sits between the urgent byte and the decoy, on a TLS port.
        let with_fast: Vec<_> = compile(
            &build_config(&json!({
                "links": [REALITY], "evasion": "auto", "auto_decoy": true, "auto_fast_open": true,
            }))
            .unwrap(),
        )
        .outbounds
        .iter()
        .filter_map(|o| o.stream.evasion.sni_desync.as_ref().map(|d| d.method))
        .collect();
        assert_eq!(
            with_fast,
            [
                zero_config::SniMethod::Urgent,
                zero_config::SniMethod::FastOpen,
                zero_config::SniMethod::Decoy
            ]
        );
        // The record version and the empty record sit between the urgent byte
        // and Fast Open.
        let with_record: Vec<_> = compile(
            &build_config(&json!({
                "links": [REALITY], "evasion": "auto", "auto_decoy": true,
                "auto_fast_open": true, "auto_record": true,
            }))
            .unwrap(),
        )
        .outbounds
        .iter()
        .filter_map(|o| o.stream.evasion.sni_desync.as_ref().map(|d| d.method))
        .collect();
        assert_eq!(
            with_record,
            [
                zero_config::SniMethod::Urgent,
                zero_config::SniMethod::Record,
                zero_config::SniMethod::FastOpen,
                zero_config::SniMethod::Decoy
            ]
        );
        // The empty record is for a link with ordinary TLS; REALITY drops it.
        let with_tls: Vec<_> = compile(
            &build_config(&json!({
                "links": [WS_TLS], "evasion": "auto", "auto_decoy": true,
                "auto_fast_open": false, "auto_record": true,
            }))
            .unwrap(),
        )
        .outbounds
        .iter()
        .filter_map(|o| o.stream.evasion.sni_desync.as_ref().map(|d| d.method))
        .collect();
        assert_eq!(
            with_tls,
            [
                zero_config::SniMethod::Urgent,
                zero_config::SniMethod::Record,
                zero_config::SniMethod::EmptyRecord,
                zero_config::SniMethod::Decoy
            ]
        );
        // Not when the device cannot, and not on top of the user's own switch.
        assert!(!decoys(json!({"links": [REALITY], "evasion": "auto"})).contains(&true));
        assert_eq!(
            decoys(
                json!({"links": [REALITY], "evasion": "auto", "auto_decoy": true, "sni_spoof": true})
            ),
            [true]
        );
        assert!(
            !decoys(json!({"links": [REALITY], "evasion": "off", "auto_decoy": true}))
                .contains(&true)
        );
    }

    /// A Cloudflare link on 443 gets the same link on the other ports
    /// Cloudflare answers on, after the others; a link elsewhere gets none.
    #[test]
    fn auto_adds_other_cloudflare_ports_for_a_cloudflare_link() {
        let ports = |link: &str| -> Vec<u16> {
            compile(&build_config(&json!({"links": [link], "evasion": "auto"})).unwrap())
                .outbounds
                .iter()
                .filter_map(|o| o.endpoint().map(|(_, port)| port))
                .collect()
        };
        let worker = "vless://00000000-0000-0000-0000-000000000002@w.example.workers.dev:443\
            ?security=tls&sni=w.example.workers.dev&type=ws&path=%2Fws&encryption=none#w";
        let found = ports(worker);
        assert_eq!(found[found.len() - 2..], ALT_PORTS);
        assert!(found[0] == 443);
        assert!(ports(WS_TLS).iter().all(|port| !ALT_PORTS.contains(port)));
    }

    /// The decoy name discovery stamps into a spoof comes from the bundled
    /// allow-listed pool, not a single hard-coded host, and is the same for a
    /// given server every time, so a flow does not flap between names and one
    /// name a network throttles costs only the servers that drew it.
    #[test]
    fn the_spoof_decoy_name_is_drawn_from_the_pool_and_stays_put() {
        let names = |request: Value| -> Vec<String> {
            compile(&build_config(&request).unwrap())
                .outbounds
                .iter()
                .filter_map(|o| o.stream.evasion.sni_desync.as_ref())
                .map(|desync| desync.fake_sni.to_string())
                .collect()
        };
        let request = json!({"links": [REALITY], "sni_spoof": true});
        let first = names(request.clone());
        assert!(!first.is_empty(), "a spoof was generated");
        for name in &first {
            assert!(
                zero_evasion::domestic::all().any(|pooled| pooled == name),
                "{name} is not in the pool"
            );
        }
        // Same server, same name on a rebuild — no flapping.
        assert_eq!(first, names(request));
    }

    /// The model refuses any TCP evasion under ShadowTLS, so discovery must never
    /// add one: a fragment or a fake-SNI packet on such a link would make the
    /// whole generated config fail to compile.
    #[test]
    fn shadowtls_is_never_fragmented_or_spoofed() {
        let (config, _) = zero_config::parse_config(&json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "relay.example", "port": 443,
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "AAECAwQFBgcICQoLDA0ODw=="
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {
                        "password": "stls", "tls": {"serverName": "www.microsoft.com"}
                    }
                }
            }]
        }))
        .unwrap();
        let outbound = &config.outbounds[0];
        assert!(!fragmentable(outbound));
        assert!(!sni_spoofable(outbound));
    }

    #[test]
    fn sni_spoof_is_off_by_default_and_skips_quic() {
        let off = compile(&build_config(&json!({"links": [REALITY]})).unwrap());
        assert!(off.outbounds[0].stream.evasion.sni_desync.is_none());
        // A QUIC carrier has no TCP hello to hide behind: never spoofed.
        let quic =
            compile(&build_config(&json!({"links": [HYSTERIA2], "sni_spoof": true})).unwrap());
        assert!(quic.outbounds[0].stream.evasion.sni_desync.is_none());
    }

    #[test]
    fn unmatched_traffic_defaults_through_the_tunnel_not_direct() {
        // The default outbound — where the router sends anything no rule
        // matched — must be the proxy, never `direct`/`block`. A fail-open to
        // direct would carry unrouted destinations over the real IP and leak
        // it. This locks that invariant against a future reordering.
        let compiled = compile(&build_config(&json!({"links": [REALITY]})).unwrap());
        let default = compiled.default_outbound().expect("a default outbound");
        assert!(
            default.tag.starts_with("proxy"),
            "default outbound is {:?}, not the tunnel — traffic would leak direct",
            default.tag
        );
    }

    #[test]
    fn auto_leaves_non_tls_links_alone() {
        // A Shadowsocks link has no ClientHello to split, so the sweep must not
        // touch it: one outbound, no fragment, no balancer.
        let config = build_config(&json!({
            "links": [SS], "evasion": "auto"
        }))
        .unwrap();
        let compiled = compile(&config);
        // proxy + direct + block + dns-out (vpn mode); the SS link is untouched.
        assert_eq!(compiled.outbounds.len(), 4);
        assert!(compiled.outbounds[0].stream.evasion.tcp_fragment.is_none());
        assert!(compiled.routing.balancers.is_empty());
    }

    #[test]
    fn quic_carriers_are_left_unfragmented() {
        // Hysteria2/TUIC run over QUIC/UDP: no TCP ClientHello to split, and the
        // model forbids TCP-shaped evasion on a QUIC carrier. So the fragment
        // sweep must skip them — one plain outbound, no fragment, no balancer,
        // whichever evasion mode is asked for.
        for mode in ["strong", "auto"] {
            let config = build_config(&json!({
                "links": [HYSTERIA2], "evasion": mode
            }))
            .unwrap();
            let proxies = config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o["tag"].as_str().is_some_and(|t| t.starts_with("proxy")))
                .count();
            assert_eq!(proxies, 1, "mode {mode}");

            let compiled = compile(&config);
            let quic = compiled
                .outbounds
                .iter()
                .find(|o| o.tag.as_ref() == "proxy")
                .unwrap();
            assert!(quic.stream.evasion.is_empty(), "mode {mode}");
            assert!(compiled.routing.balancers.is_empty(), "mode {mode}");
        }
    }

    #[test]
    fn clean_ips_reach_the_observatory() {
        let config = build_config(&json!({
            "links": [WS_TLS], "clean_ips": ["104.16.1.2:443", "172.64.0.9:2053"]
        }))
        .unwrap();
        let compiled = compile(&config);
        let clean = compiled
            .observatory
            .as_ref()
            .unwrap()
            .clean_ip
            .as_ref()
            .unwrap();
        assert_eq!(clean.candidates.len(), 2);
    }

    #[test]
    fn the_warp_order_setting_overrides_what_a_warp_link_says() {
        let account = crate::warp::link_with_exits(
            &zero_config::share_link::warp_link(
                &json!({"route": "masque-h2", "masque": {
                    "privateKey": "AAAA", "serverPublicKey": "AAAA", "address": "172.16.0.2"
                }}),
                "WARP",
            ),
            &["trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#x".to_string()],
            zero_config::HybridMode::WarpFirst,
            false,
        )
        .unwrap();
        let mode = |order: Option<&str>| {
            let mut request = json!({"links": [account], "mode": "proxy"});
            if let Some(order) = order {
                request["warp_order"] = order.into();
            }
            let config = build_config(&request).unwrap();
            let link = config["outbounds"][0]["link"].as_str().unwrap().to_string();
            crate::warp::summarize(&link).unwrap().hybrid
        };
        assert_eq!(mode(None), zero_config::HybridMode::WarpFirst);
        // Auto keeps the order the account was written with.
        assert_eq!(mode(Some("auto")), zero_config::HybridMode::WarpFirst);
        assert_eq!(
            mode(Some("server-first")),
            zero_config::HybridMode::ServerFirst
        );
        assert_eq!(mode(Some("warp-first")), zero_config::HybridMode::WarpFirst);
        assert!(build_config(&json!({"links": [account], "warp_order": "sideways"})).is_err());
    }

    /// "Allow insecure" reaches every outbound the builder makes from a link
    /// (the plain one and each evasion variant) and nothing else, and is off
    /// unless asked for.
    #[test]
    fn allow_insecure_is_off_by_default_and_reaches_every_link_variant() {
        let link = "trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#x";
        let proxies = |config: &Value| -> Vec<Value> {
            config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o.get("link").is_some())
                .cloned()
                .collect()
        };
        let plain = build_config(&json!({"links": [link], "mode": "proxy"})).unwrap();
        assert!(proxies(&plain).len() > 1, "auto evasion makes variants");
        assert!(proxies(&plain)
            .iter()
            .all(|o| o.get("allowInsecure").is_none()));
        let loose =
            build_config(&json!({"links": [link], "mode": "proxy", "allow_insecure": true}))
                .unwrap();
        assert_eq!(proxies(&loose).len(), proxies(&plain).len());
        assert!(proxies(&loose)
            .iter()
            .all(|o| o["allowInsecure"] == json!(true)));
        // And it compiles into outbounds that really skip the check.
        let (generation, _) =
            zero_config::compile_config(&loose, zero_core::GenerationId(1)).unwrap();
        for outbound in generation
            .config
            .outbounds
            .iter()
            .filter(|o| matches!(o.protocol, zero_config::OutboundProtocol::Trojan(_)))
        {
            let zero_config::Security::Tls(tls) = &outbound.stream.security else {
                panic!("expected certificate TLS");
            };
            assert!(tls.allow_insecure);
        }
    }

    /// A routing profile's rules come right after the DNS capture and ahead
    /// of the built-in ones; "through the tunnel" is the balancer when there
    /// is one and the proxy when there is not.
    #[test]
    fn profile_rules_come_first_and_proxy_follows_the_balancer() {
        let profile = json!([
            {"action": "proxy", "domain": ["domain:digikala.com"]},
            {"action": "block", "process": ["self/"]},
        ]);
        let single = build_config(&json!({
            "links": [SS], "evasion": "off", "routing_rules": profile,
        }))
        .unwrap();
        compile(&single);
        let rules = single["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], json!("dns-out"));
        assert_eq!(rules[1]["domain"], json!(["domain:digikala.com"]));
        assert_eq!(rules[1]["outboundTag"], json!("proxy"));
        assert_eq!(rules[2]["process"], json!(["self/"]));
        assert_eq!(rules[2]["outboundTag"], json!("block"));

        let several = build_config(&json!({
            "links": [SS, WS_TLS], "routing_rules": profile,
        }))
        .unwrap();
        compile(&several);
        let rules = several["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[1]["balancerTag"], json!("auto"));
        assert!(rules[1].get("outboundTag").is_none());
        assert_eq!(rules[2]["outboundTag"], json!("block"));
    }

    #[test]
    fn iran_direct_off_removes_the_domestic_rules_but_keeps_private_ranges_local() {
        let config =
            build_config(&json!({"links": [SS], "iran_direct": false, "block_quic": false}))
                .unwrap();
        compile(&config);
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert!(!rules
            .iter()
            .any(|rule| rule["ip"] == json!(IRAN_DIRECT_IPS)));
        assert!(rules
            .iter()
            .any(|rule| rule["ip"] == json!(["geoip:private"])));
        assert!(!rules.iter().any(|rule| rule["port"] == 443));
    }

    #[test]
    fn a_given_asset_directory_is_always_used_and_only_fetched_into_when_empty() {
        let dir =
            std::env::temp_dir().join(format!("zero-discovery-assets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Empty: the rule sets are still configured (this was the bug: no
        // assets block, so nothing ever downloaded them), and the core may
        // fetch them as a fallback.
        let without = build_config_with_assets(&json!({"links": [SS]}), Some(&dir)).unwrap();
        assert_eq!(without["assets"]["directory"], json!(dir.to_string_lossy()));
        assert_eq!(without["assets"]["autoUpdate"], json!(true));
        // The app's bundled files in place: loaded, never replaced.
        std::fs::write(dir.join("geosite.dat"), b"x").unwrap();
        std::fs::write(dir.join("geoip.dat"), b"x").unwrap();
        let with = build_config_with_assets(&json!({"links": [SS]}), Some(&dir)).unwrap();
        assert_eq!(with["assets"]["directory"], json!(dir.to_string_lossy()));
        assert_eq!(with["assets"]["autoUpdate"], json!(false));
        // Both shapes compile.
        for config in [&without, &with] {
            zero_config::compile_config(config, zero_core::GenerationId(1)).unwrap();
        }
        // No directory given: no assets block, as before.
        assert!(build_config(&json!({"links": [SS]}))
            .unwrap()
            .get("assets")
            .is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_requests_are_explained() {
        assert!(build_config(&json!({"links": []}))
            .unwrap_err()
            .contains("link"));
        assert!(build_config(&json!({"links": ["vless://nope"]}))
            .unwrap_err()
            .starts_with("links[0]"));
        assert!(build_config(&json!({"links": [SS], "mode": "tun"})).is_err());
        assert!(build_config(&json!({"links": [SS], "evasion": "max"})).is_err());
        assert!(build_config(&json!({"links": [SS], "tun": {"mtu": 100}})).is_err());
        assert!(build_config(&json!({"links": [SS], "dns": {"remote": "nowhere"}})).is_err());
        assert!(build_config(&json!("not an object")).is_err());
    }
}
