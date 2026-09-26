//! Ready-made configuration for the Iranian network (PLAN-02).
//!
//! Two facts drive everything here, and they pull in opposite directions
//! (PLAN-02 §3.5):
//!
//! * **Censorship** blocks outbound traffic. The remedy is to tunnel out.
//! * **Sanctions** block inbound traffic from Iranian addresses. The remedy is
//!   the opposite — stay on an Iranian address and resolve through a domestic
//!   anti-sanction resolver, because a foreign datacenter address is blocked
//!   harder than a residential Iranian one.
//!
//! A configuration that models only the first breaks every sanctioned service;
//! one that models only the second is simply censored. So the preset emits
//! three resolver tiers and a routing table with three verdicts, and pins each
//! encrypted resolver's own address so bootstrap resolution cannot be poisoned
//! before the tunnel exists.
//!
//! Presets emit configuration JSON rather than a `RuntimeConfig` directly. That
//! keeps one validation path: a preset is parsed and checked exactly like a
//! hand-written config, and cannot express something the parser would reject.

use serde_json::{json, Value};

/// Cloudflare's HTTPS port set. When 443 is throttled these often survive,
/// which is the cheapest rung of the CDN ladder (PLAN-02 §3.6).
pub const CDN_HTTPS_PORTS: [u16; 6] = [443, 8443, 2053, 2083, 2087, 2096];

/// Cloudflare's cleartext port set. Present for completeness; a preset never
/// selects one, because cleartext fronting has no handshake to hide inside.
pub const CDN_HTTP_PORTS: [u16; 7] = [80, 8080, 2052, 2082, 2086, 2095, 8880];

/// Encrypted resolvers reached through the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDns {
    /// DoH to Cloudflare by address, so the resolver's own name needs no
    /// lookup.
    Cloudflare,
    Google,
    Quad9,
    AdGuard,
}

impl RemoteDns {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "cloudflare" | "cf" => Self::Cloudflare,
            "google" => Self::Google,
            "quad9" => Self::Quad9,
            "adguard" => Self::AdGuard,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Google => "google",
            Self::Quad9 => "quad9",
            Self::AdGuard => "adguard",
        }
    }

    /// The resolver URL. Addresses are used in place of names deliberately:
    /// a DoH endpoint named by hostname needs a bootstrap lookup, and that
    /// lookup happens on the censored network before any tunnel exists.
    pub fn url(self) -> &'static str {
        match self {
            Self::Cloudflare => "https://1.1.1.1/dns-query",
            Self::Google => "https://8.8.8.8/dns-query",
            Self::Quad9 => "https://9.9.9.9/dns-query",
            Self::AdGuard => "https://94.140.14.14/dns-query",
        }
    }

    /// Hostname/address pairs pinned into `hosts`, so the human-readable form
    /// of the same resolver also resolves without a query.
    pub fn pinned_hosts(self) -> &'static [(&'static str, &'static [&'static str])] {
        match self {
            Self::Cloudflare => &[("cloudflare-dns.com", &["1.1.1.1", "1.0.0.1"])],
            Self::Google => &[("dns.google", &["8.8.8.8", "8.8.4.4"])],
            Self::Quad9 => &[("dns.quad9.net", &["9.9.9.9", "149.112.112.112"])],
            Self::AdGuard => &[("dns.adguard-dns.com", &["94.140.14.14", "94.140.15.15"])],
        }
    }
}

/// Plain resolvers used directly for domestic names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDns {
    Google,
    Cloudflare,
    /// The platform resolver. Correct only outside a full tunnel; inside one
    /// it recurses back through the tunnel it is meant to bypass.
    System,
}

impl LocalDns {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "google" => Self::Google,
            "cloudflare" | "cf" => Self::Cloudflare,
            "system" | "localhost" => Self::System,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Cloudflare => "cloudflare",
            Self::System => "system",
        }
    }

    pub fn server(self) -> &'static str {
        match self {
            Self::Google => "8.8.8.8",
            Self::Cloudflare => "1.1.1.1",
            Self::System => "localhost",
        }
    }
}

/// Iranian anti-sanction resolvers. These answer sanctioned names with a
/// domestic relay address, which only works when the connection to it also
/// originates from an Iranian address — hence `DirectVia` rather than `Proxy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiSanctionDns {
    Shecan,
    Electro,
    Begzar,
    Radar,
    /// Resolve sanctioned names with the ordinary local resolver. Correct when
    /// the user is not on an Iranian address at all.
    None,
}

impl AntiSanctionDns {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "shecan" => Self::Shecan,
            "electro" => Self::Electro,
            "begzar" => Self::Begzar,
            "radar" => Self::Radar,
            "none" | "off" => Self::None,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shecan => "shecan",
            Self::Electro => "electro",
            Self::Begzar => "begzar",
            Self::Radar => "radar",
            Self::None => "none",
        }
    }

    pub fn servers(self) -> &'static [&'static str] {
        match self {
            Self::Shecan => &["178.22.122.100", "185.51.200.2"],
            Self::Electro => &["78.157.42.100", "78.157.42.101"],
            Self::Begzar => &["185.55.226.26", "185.55.225.25"],
            Self::Radar => &["10.202.10.10", "10.202.10.11"],
            Self::None => &[],
        }
    }
}

/// Services that block Iranian addresses from the outside. These must be
/// reached *from* Iran, not through a foreign exit, so they get the third
/// routing verdict rather than the proxy.
pub const SANCTIONED_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "docker.com",
    "docker.io",
    "gcr.io",
    "adobe.com",
    "adobelogin.com",
    "intel.com",
    "nvidia.com",
    "amd.com",
    "oracle.com",
    "java.com",
    "jetbrains.com",
    "unity.com",
    "unity3d.com",
    "epicgames.com",
    "autodesk.com",
    "mathworks.com",
    "ansys.com",
    "tableau.com",
    "sandbox.google.com",
    "developer.android.com",
    "android.com",
    "cloud.google.com",
    "firebase.google.com",
    "azure.com",
    "visualstudio.com",
    "microsoft.com",
    "windowsupdate.com",
    "slack.com",
    "notion.so",
    "figma.com",
    "vercel.com",
    "netlify.com",
    "digitalocean.com",
    "linode.com",
    "heroku.com",
    "bitbucket.org",
    "sourceforge.net",
    "codecov.io",
    "sentry.io",
    "datadoghq.com",
    "asus.com",
    "hp.com",
    "lenovo.com",
    "deepmind.com",
    "deepmind.google",
];

/// Domestic destinations that must never be tunnelled: sending them abroad is
/// slower, and for banking and government services often simply refused.
pub const IRAN_DIRECT_DOMAINS: &[&str] = &[
    "geosite:category-ir",
    "domain:ir",
    "domain:xn--mgba3a4f16a",
    "domain:aparat.com",
    "domain:digikala.com",
    "domain:varzesh3.com",
    "domain:snapp.ir",
    "domain:divar.ir",
    "domain:shaparak.ir",
    "domain:sb24.com",
    "domain:cafebazaar.ir",
    "domain:myket.ir",
];

pub const IRAN_DIRECT_IPS: &[&str] = &["geoip:ir", "geoip:private"];

/// The rule-set mirrors used when a preset is asked to manage geodata itself.
/// Two mirrors for each file, because a single blocked host is the common case
/// on the network this preset exists for.
pub fn default_asset_files() -> Value {
    json!([
        {
            "name": "geosite.dat",
            "kind": "geosite",
            "urls": [
                "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
                "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@release/dlc.dat"
            ]
        },
        {
            "name": "geoip.dat",
            "kind": "geoip",
            "urls": [
                "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
                "https://cdn.jsdelivr.net/gh/v2fly/geoip@release/geoip.dat"
            ]
        }
    ])
}

#[derive(Debug, Clone)]
pub struct IranPreset {
    /// Proxy outbound objects, in Xray JSON form. Either full outbound objects
    /// or the `{"link": "vless://…"}` short form; the first is the default
    /// proxy and receives every session no rule matched.
    pub outbounds: Vec<Value>,
    pub listen: String,
    pub socks_port: u16,
    /// `None` omits the HTTP inbound.
    pub http_port: Option<u16>,
    pub remote_dns: RemoteDns,
    /// A user-supplied resolver that overrides [`Self::remote_dns`] for the
    /// encrypted "everything else" tier. Any form `ResolverEndpoint::parse`
    /// accepts (a bare IP like `8.8.8.8`, `tls://…`, `https://…/dns-query`,
    /// …). `None` keeps the built-in `remote_dns`.
    pub custom_remote_dns: Option<String>,
    pub local_dns: LocalDns,
    pub anti_sanction_dns: AntiSanctionDns,
    pub custom_anti_sanction_dns: Option<String>,
    pub block_ads: bool,
    /// Enable ClientHello fragmentation on every TLS-bearing outbound from the
    /// start, instead of waiting for the planner to climb to that rung.
    pub fragment: bool,
    pub manage_assets: bool,
    pub asset_directory: Option<String>,
    /// Bounded CDN edge candidates for clean-IP measurement, as `ip:port`.
    pub clean_ip_candidates: Vec<String>,
    pub clean_ip_host: String,
}

impl Default for IranPreset {
    fn default() -> Self {
        Self {
            outbounds: Vec::new(),
            listen: "127.0.0.1".into(),
            socks_port: 10808,
            http_port: Some(10809),
            remote_dns: RemoteDns::Google,
            custom_remote_dns: None,
            local_dns: LocalDns::Google,
            anti_sanction_dns: AntiSanctionDns::Shecan,
            custom_anti_sanction_dns: None,
            block_ads: true,
            fragment: false,
            manage_assets: true,
            asset_directory: None,
            clean_ip_candidates: Vec::new(),
            clean_ip_host: "www.speedtest.net".into(),
        }
    }
}

/// Wrap share links as link-form outbound objects.
pub fn outbounds_from_links<I, S>(links: I) -> Vec<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    links
        .into_iter()
        .map(|link| json!({"link": link.as_ref()}))
        .collect()
}

/// Tag used for the proxy outbound when the caller does not name one.
const PROXY_TAG: &str = "proxy";
const DIRECT_TAG: &str = "direct";
const BLOCK_TAG: &str = "block";
const ANTI_SANCTION_TAG: &str = "anti-sanction";
const LOCAL_TAG: &str = "local";
const REMOTE_TAG: &str = "remote";

impl IranPreset {
    /// Render the preset as Xray-shaped configuration JSON.
    ///
    /// With no proxy outbounds supplied, a placeholder tagged `proxy` stands in
    /// so the routing table is complete and the first outbound — which is the
    /// no-match default — is still the proxy rather than `direct`. Sending
    /// unmatched traffic direct would be a silent, total bypass.
    pub fn build(&self) -> Value {
        let mut outbounds = Vec::with_capacity(self.outbounds.len() + 3);
        if self.outbounds.is_empty() {
            outbounds.push(json!({"tag": PROXY_TAG, "protocol": "freedom"}));
        }
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let mut outbound = outbound.clone();
            if let Some(object) = outbound.as_object_mut() {
                object.entry("tag").or_insert_with(|| {
                    if index == 0 {
                        json!(PROXY_TAG)
                    } else {
                        json!(format!("{PROXY_TAG}-{index}"))
                    }
                });
                if self.fragment {
                    if object.contains_key("link") {
                        // A link describes the server, not this network, so
                        // evasion is layered on rather than folded into it.
                        object.entry("evasion").or_insert_with(|| {
                            json!({"fragment": {
                                "packets": "tlshello",
                                "length": "100-200",
                                "interval": "1-1",
                            }})
                        });
                    } else {
                        apply_fragment(object);
                    }
                }
            }
            outbounds.push(outbound);
        }
        outbounds.push(json!({"tag": DIRECT_TAG, "protocol": "freedom"}));
        outbounds.push(json!({"tag": BLOCK_TAG, "protocol": "blackhole"}));

        let mut config = json!({
            "log": {"loglevel": "warning"},
            "inbounds": self.inbounds(),
            "outbounds": outbounds,
            "dns": self.dns(),
            "routing": {"rules": self.rules()},
        });

        if self.manage_assets {
            let mut assets = json!({
                "refreshInterval": "24h",
                "retryInterval": "15m",
                "files": default_asset_files(),
            });
            if let Some(directory) = self.asset_directory.as_deref() {
                assets["directory"] = json!(directory);
            }
            config["assets"] = assets;
        }

        if !self.clean_ip_candidates.is_empty() {
            config["observatory"] = json!({
                "probeUrl": "https://www.gstatic.com/generate_204",
                "probeInterval": "300s",
                "cleanIp": {
                    "candidates": self.clean_ip_candidates,
                    "host": self.clean_ip_host,
                    "path": "/",
                },
            });
        }

        config
    }

    fn inbounds(&self) -> Value {
        let mut inbounds = vec![json!({
            "tag": "socks-in",
            "listen": self.listen,
            "port": self.socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]},
        })];
        if let Some(port) = self.http_port {
            inbounds.push(json!({
                "tag": "http-in",
                "listen": self.listen,
                "port": port,
                "protocol": "http",
                "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
            }));
        }
        Value::Array(inbounds)
    }

    /// The anti-sanction resolver addresses to use: the user's custom one when
    /// it is set and usable (a bare IP or an IP-addressed DoH/DoT/DoQ URL —
    /// a hostname is refused because a censored network cannot bootstrap it),
    /// otherwise the built-in resolver's addresses. Empty means the third
    /// verdict is off entirely (`AntiSanctionDns::None` with no custom).
    fn anti_sanction_servers(&self) -> Vec<String> {
        let custom = self
            .custom_anti_sanction_dns
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter(|value| {
                crate::dns::ResolverEndpoint::parse(value)
                    .is_some_and(|endpoint| !endpoint.needs_bootstrap())
            });
        match custom {
            Some(custom) => vec![custom.to_string()],
            None => self
                .anti_sanction_dns
                .servers()
                .iter()
                .map(|address| (*address).to_string())
                .collect(),
        }
    }

    /// Three resolver tiers plus pinned bootstrap addresses.
    fn dns(&self) -> Value {
        let mut servers: Vec<Value> = Vec::new();

        // Tier 1 — sanctioned names, answered by a domestic resolver. Scoped
        // to the sanctioned list so it cannot become a general resolver, and
        // tagged so `DirectVia` can name it.
        let anti_sanction = self.anti_sanction_servers();
        if !anti_sanction.is_empty() {
            for address in anti_sanction {
                servers.push(json!({
                    "address": address,
                    "domains": SANCTIONED_DOMAINS
                        .iter()
                        .map(|domain| format!("domain:{domain}"))
                        .collect::<Vec<_>>(),
                    "tag": ANTI_SANCTION_TAG,
                }));
            }
        }

        // Tier 2 — domestic names, resolved directly. `expectIPs` rejects an
        // answer outside Iran, which is what a poisoned or hijacked response
        // to a domestic name looks like.
        servers.push(json!({
            "address": self.local_dns.server(),
            "domains": IRAN_DIRECT_DOMAINS,
            "expectIPs": ["geoip:ir"],
            "tag": LOCAL_TAG,
        }));

        // Tier 3 — everything else, encrypted and through the tunnel. A
        // user-supplied resolver, if valid, replaces the built-in one; its
        // hostname (if any) still needs a pinned bootstrap address, so a
        // custom DoH URL named by hostname keeps the built-in resolver's
        // pinned hosts as a best-effort bootstrap.
        let custom_remote = self
            .custom_remote_dns
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter(|value| crate::dns::ResolverEndpoint::parse(value).is_some());
        let remote_address = custom_remote.unwrap_or_else(|| self.remote_dns.url());
        servers.push(json!({
            "address": remote_address,
            "tag": REMOTE_TAG,
        }));

        let mut hosts = serde_json::Map::new();
        for (name, addresses) in self.remote_dns.pinned_hosts() {
            hosts.insert((*name).to_string(), json!(addresses));
        }

        json!({
            "servers": servers,
            "hosts": Value::Object(hosts),
            "queryStrategy": "UseIP",
            // There is deliberately no leak-policy key here: the parser pins
            // `LeakPolicy::Strict` unconditionally, so a failed encrypted
            // lookup fails rather than silently retrying in cleartext. Emitting
            // a key that the parser ignores would only suggest it is optional.
            "tag": "dns-out",
        })
    }

    fn rules(&self) -> Value {
        let mut rules: Vec<Value> = Vec::new();

        if self.block_ads {
            rules.push(json!({
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": BLOCK_TAG,
            }));
        }

        // Sanctioned services, before the domestic rules: several of them have
        // domestic CDN presence and would otherwise match a broader rule. The
        // rule is emitted only when a resolver actually backs the tag — the
        // built-in enum, or a usable custom resolver — so the two never
        // disagree about whether the third verdict exists.
        if !self.anti_sanction_servers().is_empty() {
            rules.push(json!({
                "type": "field",
                "domain": SANCTIONED_DOMAINS
                    .iter()
                    .map(|domain| format!("domain:{domain}"))
                    .collect::<Vec<_>>(),
                "directVia": ANTI_SANCTION_TAG,
            }));
        }

        rules.push(json!({
            "type": "field",
            "domain": IRAN_DIRECT_DOMAINS,
            "outboundTag": DIRECT_TAG,
        }));
        rules.push(json!({
            "type": "field",
            "ip": IRAN_DIRECT_IPS,
            "outboundTag": DIRECT_TAG,
        }));
        // Local discovery protocols have no business leaving the machine.
        rules.push(json!({
            "type": "field",
            "port": "137-139",
            "network": "udp",
            "outboundTag": BLOCK_TAG,
        }));

        Value::Array(rules)
    }
}

/// Turn on ClientHello fragmentation for an outbound that carries TLS.
///
/// Skipped when ECH is configured: ECH encrypts the SNI, so there is no
/// plaintext name left to split and fragmenting only adds latency and a timing
/// signature (PLAN-02 §3.6).
fn apply_fragment(outbound: &mut serde_json::Map<String, Value>) {
    let Some(stream) = outbound
        .entry("streamSettings")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return;
    };
    let security = stream
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if security == "none" {
        return;
    }
    let has_ech = stream
        .get("tlsSettings")
        .and_then(|tls| tls.get("echConfigList"))
        .is_some();
    if has_ech {
        return;
    }
    stream.entry("fragment").or_insert_with(|| {
        json!({
            "packets": "tlshello",
            "length": "100-200",
            "interval": "1-1",
        })
    });
}

/// Build a complete configuration from already-parsed proxy outbounds.
///
/// Share links are parsed by `share_link`, which yields an `Outbound` rather
/// than JSON. Rather than serialising that back to JSON — a lossy round trip
/// that would silently drop any field the serialiser forgot — the preset's own
/// JSON is parsed first and its placeholder proxy is then replaced with the
/// real outbounds. Everything the preset generates still goes through the
/// ordinary parser; the proxies keep the exact shape the link parser produced.
pub fn build_with_outbounds(
    preset: &IranPreset,
    proxies: Vec<crate::model::Outbound>,
) -> Result<crate::model::RuntimeConfig, String> {
    if proxies.is_empty() {
        return Err("an Iran preset needs at least one proxy outbound".into());
    }
    let (mut config, _) = crate::parse_config(&preset.build())?;

    let mut outbounds: Vec<crate::model::Outbound> = Vec::with_capacity(proxies.len() + 2);
    for (index, mut proxy) in proxies.into_iter().enumerate() {
        // The routing table names `proxy`; the first proxy must answer to it
        // however the share link was labelled.
        proxy.tag = if index == 0 {
            std::sync::Arc::from(PROXY_TAG)
        } else if proxy.tag.is_empty() || proxy.tag.as_ref() == PROXY_TAG {
            std::sync::Arc::from(format!("{PROXY_TAG}-{index}").as_str())
        } else {
            proxy.tag
        };
        if preset.fragment {
            enable_fragment(&mut proxy);
        }
        outbounds.push(proxy);
    }
    // Keep the preset's own direct/block outbounds, which the routing rules
    // name, and drop the placeholder proxy.
    for outbound in config.outbounds.iter() {
        if outbound.tag.as_ref() != PROXY_TAG {
            outbounds.push(outbound.clone());
        }
    }
    config.outbounds = outbounds.into_boxed_slice();
    config.validate()?;
    Ok(config)
}

/// Turn on ClientHello fragmentation for a compiled outbound, with the same
/// ECH exclusion as the JSON path.
fn enable_fragment(outbound: &mut crate::model::Outbound) {
    if matches!(outbound.stream.security, crate::model::Security::None) {
        return;
    }
    if matches!(
        &outbound.stream.security,
        crate::model::Security::Tls(crate::model::TlsConfig { ech: Some(_), .. })
    ) {
        return;
    }
    if outbound.stream.evasion.tcp_fragment.is_none() {
        outbound.stream.evasion.tcp_fragment = Some(crate::model::FragmentConfig::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_config;

    fn vless_outbound() -> Value {
        json!({
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "203.0.113.10",
                "port": 443,
                "users": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "encryption": "none",
                    "flow": "xtls-rprx-vision"
                }]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.googletagmanager.com",
                    "fingerprint": "chrome",
                    "publicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    "shortId": "0123456789abcdef"
                }
            }
        })
    }

    #[test]
    fn the_preset_parses_as_an_ordinary_configuration() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).expect("preset must be a valid config");
        assert_eq!(config.inbounds.len(), 2);
        // proxy + direct + block
        assert_eq!(config.outbounds.len(), 3);
        assert!(config.assets.is_some());
    }

    #[test]
    fn sanctioned_domains_route_direct_via_the_anti_sanction_resolver() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let sanctioned = config
            .routing
            .rules
            .iter()
            .find(|rule| {
                matches!(&rule.target, crate::routing::RuleTarget::DirectVia { resolver }
                    if resolver.as_ref() == ANTI_SANCTION_TAG)
            })
            .expect("a DirectVia rule must exist");
        assert!(sanctioned.domains.iter().any(|pattern| matches!(
            pattern,
            crate::routing::DomainPattern::Suffix(name) if name.as_ref() == "openai.com"
        )));
    }

    #[test]
    fn the_three_resolver_tiers_are_distinct_and_tagged() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let tags: Vec<_> = config
            .dns
            .servers
            .iter()
            .filter_map(|server| server.tag.as_deref().map(str::to_owned))
            .collect();
        assert!(tags.iter().any(|tag| tag == ANTI_SANCTION_TAG));
        assert!(tags.iter().any(|tag| tag == LOCAL_TAG));
        assert!(tags.iter().any(|tag| tag == REMOTE_TAG));

        // The remote tier is the only catch-all; the other two are scoped, or
        // they would answer for names they have no business answering.
        for server in config.dns.servers.iter() {
            if server.tag.as_deref() == Some(REMOTE_TAG) {
                assert!(server.domains.is_empty());
            } else {
                assert!(!server.domains.is_empty(), "{:?} is unscoped", server.tag);
            }
        }
    }

    #[test]
    fn the_encrypted_resolver_is_named_by_address_and_its_hostname_is_pinned() {
        for remote in [
            RemoteDns::Cloudflare,
            RemoteDns::Google,
            RemoteDns::Quad9,
            RemoteDns::AdGuard,
        ] {
            let preset = IranPreset {
                outbounds: vec![vless_outbound()],
                remote_dns: remote,
                ..IranPreset::default()
            };
            let (config, _) = parse_config(&preset.build()).unwrap();
            let server = config
                .dns
                .servers
                .iter()
                .find(|server| server.tag.as_deref() == Some(REMOTE_TAG))
                .unwrap();
            // A DoH endpoint that needs a bootstrap lookup is the leak this
            // tier exists to avoid.
            assert!(
                !server.endpoint.needs_bootstrap(),
                "{remote:?} would need bootstrap DNS"
            );
            for (name, _) in remote.pinned_hosts() {
                assert!(config.dns.hosts.contains_key(*name), "{name} is not pinned");
            }
        }
    }

    #[test]
    fn dns_never_falls_back_to_the_platform_resolver() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        // Strict is not configurable, and this asserts that: the preset must
        // not be able to produce a configuration that falls back to cleartext.
        assert_eq!(config.dns.leak_policy, crate::dns::LeakPolicy::Strict);
        let mut with_override = preset.build();
        with_override["dns"]["leakPolicy"] = json!("fallback");
        let (config, _) = parse_config(&with_override).unwrap();
        assert_eq!(config.dns.leak_policy, crate::dns::LeakPolicy::Strict);
    }

    #[test]
    fn a_custom_remote_resolver_replaces_the_encrypted_tier_address() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            remote_dns: RemoteDns::Google,
            custom_remote_dns: Some("9.9.9.9".to_string()),
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let server = config
            .dns
            .servers
            .iter()
            .find(|server| server.tag.as_deref() == Some(REMOTE_TAG))
            .expect("the remote tier must exist");
        // The user's resolver, not Google's built-in DoH URL.
        assert!(!server.endpoint.needs_bootstrap());
        assert!(matches!(
            &server.endpoint,
            crate::dns::ResolverEndpoint::Udp { address, .. } if address.is_ip()
        ));
    }

    #[test]
    fn an_unparseable_custom_remote_resolver_is_ignored() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            remote_dns: RemoteDns::Google,
            custom_remote_dns: Some("   ".to_string()),
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let server = config
            .dns
            .servers
            .iter()
            .find(|server| server.tag.as_deref() == Some(REMOTE_TAG))
            .expect("the remote tier must exist");
        // Blank falls back to the built-in resolver.
        assert!(!server.endpoint.needs_bootstrap());
    }

    #[test]
    fn disabling_anti_sanction_removes_the_third_verdict_entirely() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            anti_sanction_dns: AntiSanctionDns::None,
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        assert!(!config
            .routing
            .rules
            .iter()
            .any(|rule| matches!(rule.target, crate::routing::RuleTarget::DirectVia { .. })));
        assert!(!config
            .dns
            .servers
            .iter()
            .any(|server| server.tag.as_deref() == Some(ANTI_SANCTION_TAG)));
    }

    #[test]
    fn fragmentation_is_opt_in_and_skips_ech_outbounds() {
        let preset = IranPreset {
            outbounds: vec![vless_outbound()],
            fragment: true,
            ..IranPreset::default()
        };
        let built = preset.build();
        let stream = &built["outbounds"][0]["streamSettings"];
        assert_eq!(stream["fragment"]["packets"], json!("tlshello"));

        let mut ech = vless_outbound();
        ech["streamSettings"] = json!({
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": "edge.example", "echConfigList": "AEX+DQBB"}
        });
        let preset = IranPreset {
            outbounds: vec![ech],
            fragment: true,
            ..IranPreset::default()
        };
        let built = preset.build();
        assert!(built["outbounds"][0]["streamSettings"]
            .get("fragment")
            .is_none());
    }

    #[test]
    fn share_links_become_outbounds_without_a_lossy_re_encoding() {
        let link = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
                    ?security=reality&sni=www.googletagmanager.com&fp=chrome\
                    &pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef\
                    &flow=xtls-rprx-vision&type=tcp&encryption=none#Example";
        let preset = IranPreset {
            outbounds: outbounds_from_links([link]),
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let proxy = &config.outbounds[0];
        assert_eq!(proxy.tag.as_ref(), PROXY_TAG);

        // The link parser is the single source of truth for the mapping; the
        // preset must not alter anything it produced.
        let direct = crate::parse_link(link).unwrap().outbound;
        assert_eq!(proxy.protocol, direct.protocol);
        assert_eq!(
            format!("{:?}", proxy.stream.security),
            format!("{:?}", direct.stream.security)
        );
        assert_eq!(
            format!("{:?}", proxy.stream.transport),
            format!("{:?}", direct.stream.transport)
        );
    }

    #[test]
    fn fragmentation_layers_onto_a_link_outbound() {
        let link = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
                    ?security=reality&sni=www.googletagmanager.com&fp=chrome\
                    &pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef\
                    &type=tcp&encryption=none#Example";
        let preset = IranPreset {
            outbounds: outbounds_from_links([link]),
            fragment: true,
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        let fragment = config.outbounds[0]
            .stream
            .evasion
            .tcp_fragment
            .as_ref()
            .expect("fragmentation must reach a link-form outbound");
        assert_eq!(fragment.length.min, 100);
        assert_eq!(fragment.length.max, 200);

        // Off by default: fragmentation costs a round trip, so it is a rung
        // the planner climbs to, not a permanent tax.
        let preset = IranPreset {
            outbounds: outbounds_from_links([link]),
            ..IranPreset::default()
        };
        let (config, _) = parse_config(&preset.build()).unwrap();
        assert!(config.outbounds[0].stream.evasion.tcp_fragment.is_none());
    }

    #[test]
    fn a_link_outbound_cannot_also_declare_a_protocol() {
        let config = json!({
            "outbounds": [{
                "tag": "proxy",
                "link": "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443?encryption=none&type=tcp",
                "protocol": "freedom"
            }]
        });
        assert!(parse_config(&config)
            .unwrap_err()
            .contains("both `link` and `protocol`"));
    }

    #[test]
    fn preset_names_round_trip() {
        assert_eq!(RemoteDns::parse("CloudFlare"), Some(RemoteDns::Cloudflare));
        assert_eq!(LocalDns::parse("system"), Some(LocalDns::System));
        assert_eq!(
            AntiSanctionDns::parse("shecan"),
            Some(AntiSanctionDns::Shecan)
        );
        assert_eq!(AntiSanctionDns::parse("none"), Some(AntiSanctionDns::None));
        assert!(RemoteDns::parse("nonsense").is_none());
    }

    #[test]
    fn the_cdn_port_sets_match_the_field_tuned_values() {
        assert!(CDN_HTTPS_PORTS.contains(&2053));
        assert!(CDN_HTTPS_PORTS.contains(&8443));
        assert!(!CDN_HTTPS_PORTS.contains(&80));
        assert!(CDN_HTTP_PORTS.contains(&8880));
    }
}
