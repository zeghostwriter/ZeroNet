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

/// ClientHello chunk sizes of the fragmented variants `evasion = "auto"`
/// adds after each link's plain one. 40-80 got 10 of 10 through a throttled
/// Cloudflare edge from Tehran on 2026-09-28; 100-200 3 of 3, with slower
/// runs. BPB's sweep of twenty lengths is not needed once the split is plain
/// TCP segments, and every variant is one more outbound to probe.
const AUTO_FRAGMENT_LENGTHS: [&str; 2] = ["40-80", "100-200"];

/// How much the builder layers ClientHello fragmentation onto TLS links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evasion {
    /// No fragmentation; the link dials as described.
    Off,
    /// Each fragmentable link as is, then fragmented at each of
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
    /// Iran — 0 of 3 against 3 of 3, measured 2026-09-28.
    fragment_packets: String,
    /// Put the fragmented variants of `auto` first: the app sets this when
    /// the crowd rankings say fragmenting works better than a plain
    /// connection on this network, so a fresh connect starts with what
    /// worked for others instead of rediscovering it.
    fragment_first: bool,
    /// Inject a decoy ClientHello carrying an allow-listed SNI (raw fake-SNI
    /// desync) on every TLS/REALITY outbound. Needs CAP_NET_RAW at runtime; the
    /// engine falls back to fragmentation when it is missing.
    sni_spoof: bool,
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
            dns: DnsRequest::default(),
            log_level: "warning".into(),
            clean_ips: Vec::new(),
            assets_dir: None,
            warp_order: None,
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
    // the default) or `tlshello`. Validated here so the error names the field
    // rather than surfacing from the compiler.
    let fragment_packets = {
        let value = request.fragment_packets.trim();
        if value.is_empty() {
            "1-1".to_string()
        } else if value == "tlshello" {
            "tlshello".to_string()
        } else if zero_config::RangeU32::parse(value).is_some() {
            value.to_string()
        } else {
            return Err(format!(
                "fragment_packets must be \"tlshello\" or a range like \"1-1\", got {value:?}"
            ));
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
        let can_fragment = fragmentable(&parsed.outbound);
        let spoof = (request.sni_spoof && sni_spoofable(&parsed.outbound))
            .then(|| json!({"fakeSni": SPOOF_DECOY_SNI}));
        // Compose one outbound's evasion object from an optional fragment length
        // and the optional SNI decoy; `None` when neither applies.
        let evasion_block = |length: Option<&str>| -> Option<Value> {
            let mut block = serde_json::Map::new();
            if let Some(length) = length {
                block.insert(
                    "fragment".into(),
                    json!({"packets": fragment_packets, "length": length, "interval": "1-1"}),
                );
            }
            if let Some(spoof) = &spoof {
                block.insert("sniSpoof".into(), spoof.clone());
            }
            (!block.is_empty()).then_some(Value::Object(block))
        };
        let push = |outbounds: &mut Vec<Value>, length: Option<&str>| match evasion_block(length) {
            Some(evasion) => outbounds.push(json!({"link": parsed.link, "evasion": evasion})),
            None => outbounds.push(json!({"link": parsed.link})),
        };
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
    }
    // The balancer is keyed off how many proxy outbounds exist, not how many
    // links: one link under `auto` still expands into variants that need the
    // balancer to choose among.
    let proxy_count = outbounds.len();

    let assets_dir = request
        .assets_dir
        .clone()
        .or_else(|| assets_dir.map(Path::to_path_buf));
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
    if let Some(inbounds) = config["inbounds"].as_array_mut() {
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
fn fragmentable(outbound: &zero_config::Outbound) -> bool {
    // QUIC carriers (Hysteria2/TUIC) run over UDP: there is no TCP ClientHello
    // to split, and the model forbids layering TCP-shaped evasion on them. They
    // manage their own QUIC handshake, so leave them untouched.
    if matches!(
        outbound.protocol,
        zero_config::OutboundProtocol::Hysteria2(_) | zero_config::OutboundProtocol::Tuic(_)
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
    }
}

/// The decoy SNI stamped into a spoofed ClientHello: a widely-allow-listed
/// name, so a DPI parser sees an unblocked destination. The real hello (and
/// its true SNI) still reaches the server untouched.
const SPOOF_DECOY_SNI: &str = "www.microsoft.com";

/// Whether raw fake-SNI injection applies to this outbound. Unlike
/// fragmentation it adds a *separate* decoy packet and never touches the real
/// ClientHello, so REALITY is fine — but there must be a TCP TLS/REALITY hello
/// to hide behind, so plaintext, ECH and QUIC carriers are skipped.
fn sni_spoofable(outbound: &zero_config::Outbound) -> bool {
    if matches!(
        outbound.protocol,
        zero_config::OutboundProtocol::Hysteria2(_) | zero_config::OutboundProtocol::Tuic(_)
    ) {
        return false;
    }
    match &outbound.stream.security {
        zero_config::Security::None => false,
        zero_config::Security::Tls(tls) => tls.ech.is_none(),
        zero_config::Security::Reality(_) => true,
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
                && matches!(outbound.protocol, zero_config::OutboundProtocol::Dns)));
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
        assert!(!compiled
            .outbounds
            .iter()
            .any(|outbound| matches!(outbound.protocol, zero_config::OutboundProtocol::Dns)));
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
    /// `None` for a plain one.
    fn variant_lengths(config: &Value) -> Vec<Option<String>> {
        config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| {
                o["tag"]
                    .as_str()
                    .is_some_and(|t| t == "proxy" || t.starts_with("proxy-"))
            })
            .map(|o| {
                o["evasion"]["fragment"]["length"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn auto_tries_the_link_plain_first_then_fragmented() {
        let config = build_config(&json!({"links": [WS_TLS], "evasion": "auto"})).unwrap();
        assert_eq!(
            variant_lengths(&config),
            [None, Some("40-80".into()), Some("100-200".into())]
        );
        let compiled = compile(&config);
        // One link still gets the balancer that chooses among its variants.
        assert_eq!(compiled.routing.balancers.len(), 1);
        assert_eq!(
            compiled
                .expand_balancer(&compiled.routing.balancers[0])
                .len(),
            3
        );
        // Only the fragmented variants split the ClientHello, as TCP segments.
        let fragments: Vec<_> = compiled
            .outbounds
            .iter()
            .filter_map(|o| o.stream.evasion.tcp_fragment.as_ref())
            .collect();
        assert_eq!(fragments.len(), 2);
        assert!(fragments
            .iter()
            .all(|f| f.packets == zero_config::FragmentPackets::Range { from: 1, to: 1 }));
    }

    #[test]
    fn auto_starts_fragmented_when_others_here_found_that_works() {
        let config = build_config(&json!({
            "links": [WS_TLS], "evasion": "auto", "fragment_first": true
        }))
        .unwrap();
        assert_eq!(
            variant_lengths(&config),
            [Some("40-80".into()), Some("100-200".into()), None]
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
        assert_eq!(modes.len(), AUTO_FRAGMENT_LENGTHS.len());
        assert!(modes.iter().all(|m| *m == "1-1"));
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
