//! The supported subset of Xray's JSON configuration.
//!
//! Parsing is deliberately strict about anything security-relevant and
//! tolerant about cosmetics. Unsupported *modelled* fields are reported with
//! their JSON path rather than silently dropped, because a silently ignored
//! `allowInsecure` or `flow` is a security bug, not a compatibility gap.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;
use zero_core::{Address, Network};

use crate::dns::*;
use crate::model::*;
use crate::routing::{self, Routing, Rule, RuleTarget};

/// A non-fatal note produced while parsing.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ParseOutput {
    pub diagnostics: Vec<Diagnostic>,
}

impl ParseOutput {
    fn note(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            path: path.into(),
            message: message.into(),
        });
    }
}

type R<T> = Result<T, String>;

/// Parse one Xray config object into the compiled runtime model.
pub fn parse_config(v: &Value) -> R<(RuntimeConfig, ParseOutput)> {
    let mut out = ParseOutput::default();
    let obj = v.as_object().ok_or("config root must be an object")?;
    note_unsupported_sections(obj, &mut out);

    let log_level = obj
        .get("log")
        .and_then(|l| l.get("loglevel"))
        .and_then(Value::as_str)
        .unwrap_or("warning")
        .into();

    let inbounds = obj
        .get("inbounds")
        .and_then(Value::as_array)
        .map(|a| parse_inbounds(a, &mut out))
        .transpose()?
        .unwrap_or_default();

    let outbounds = obj
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or("config has no outbounds array")?;
    let mut outbounds = parse_outbounds(outbounds, &mut out)?;
    let mut bridges = parse_reverse(obj.get("reverse"), &mut outbounds)?;
    add_vless_reverse(
        &inbounds,
        obj.get("outbounds"),
        &mut outbounds,
        &mut bridges,
    )?;

    let routing = match obj.get("routing") {
        Some(r) => parse_routing(r, &mut out)?,
        None => Routing::default(),
    };

    let mut dns = match obj.get("dns") {
        Some(d) => parse_dns(d, &mut out)?,
        None => DnsSettings::default(),
    };
    // `leakPolicy: fallback` lets names resolve with the machine's own
    // resolver. That is right only where traffic leaves the machine directly
    // (a server); any config with a proxy outbound is a client, where it would
    // answer outside the tunnel, so a config from outside cannot ask for it.
    if !outbounds.iter().all(|o| {
        matches!(
            o.protocol,
            OutboundProtocol::Freedom { .. } | OutboundProtocol::Blackhole { .. }
        )
    }) {
        dns.leak_policy = LeakPolicy::Strict;
    }

    // `burstObservatory` is Xray's other way of probing outbounds: the same
    // idea (an address to fetch through each, how often), with the address
    // and the interval under `pingConfig`.
    let observatory = match (obj.get("observatory"), obj.get("burstObservatory")) {
        (Some(value), _) => Some(parse_observatory(value, "observatory")?),
        (None, Some(burst)) => Some(parse_burst_observatory(burst)?),
        (None, None) => None,
    };

    let assets = obj
        .get("assets")
        .map(|value| parse_assets(value, "assets"))
        .transpose()?;

    let policy = match obj.get("policy") {
        Some(policy) => parse_policy(policy, &mut out)?,
        None => Policy::default(),
    };

    let cfg = RuntimeConfig {
        policy,
        inbounds: inbounds.into_boxed_slice(),
        outbounds: outbounds.into_boxed_slice(),
        routing,
        dns,
        observatory,
        assets,
        log_level,
        bridges: bridges.into_boxed_slice(),
    };
    cfg.validate()?;
    Ok((cfg, out))
}

/// VLESS's own reverse proxy, in the accounts: a server account with
/// `reverse.tag` makes a portal of that name (an outbound routing can send
/// traffic to), and an outbound account with `reverse.tag` is a bridge that
/// dials its server with the reverse command and serves what comes back.
fn add_vless_reverse(
    inbounds: &[Inbound],
    outbound_json: Option<&Value>,
    outbounds: &mut Vec<Outbound>,
    bridges: &mut Vec<ReverseBridge>,
) -> R<()> {
    for inbound in inbounds {
        let InboundProtocol::Vless(config) = &inbound.protocol else {
            continue;
        };
        for tag in config.users.iter().filter_map(|user| user.reverse.as_ref()) {
            if outbounds.iter().any(|outbound| outbound.tag == *tag) {
                if matches!(
                    outbounds
                        .iter()
                        .find(|o| o.tag == *tag)
                        .map(|o| &o.protocol),
                    Some(OutboundProtocol::Portal { .. })
                ) {
                    continue;
                }
                return Err(format!("VLESS reverse tag {tag:?} is already an outbound"));
            }
            outbounds.push(Outbound {
                tag: Arc::clone(tag),
                protocol: OutboundProtocol::Portal {
                    domain: Arc::from(VLESS_REVERSE_HOST),
                },
                stream: StreamSettings::default(),
                mux: MuxConfig::default(),
            });
        }
    }
    for outbound in outbound_json
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if outbound.get("protocol").and_then(Value::as_str) != Some("vless") {
            continue;
        }
        let via: Arc<str> = Arc::from(outbound.get("tag").and_then(Value::as_str).unwrap_or("out"));
        let normalized = unflatten_outbound(outbound);
        let outbound = normalized.as_ref().unwrap_or(outbound);
        let users = outbound
            .get("settings")
            .and_then(|settings| settings.get("vnext"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|server| server.get("users").and_then(Value::as_array))
            .flatten();
        for user in users {
            let Some(tag) = user
                .get("reverse")
                .and_then(|reverse| reverse.get("tag"))
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            bridges.push(ReverseBridge {
                tag: Arc::from(tag),
                domain: Arc::from(VLESS_REVERSE_HOST),
                via: Some(Arc::clone(&via)),
            });
        }
    }
    Ok(())
}

/// The destination name of a VLESS reverse dial-in.
const VLESS_REVERSE_HOST: &str = "v1.rvs.cool";

/// Xray's `reverse`: `{"bridges": [{"tag", "domain"}], "portals": [...]}`.
///
/// A portal is an outbound of its own tag, added to the table here so routing
/// can send traffic to it like to any other. A bridge is not an outbound or
/// an inbound but a tag that its own connections are routed under.
fn parse_reverse(value: Option<&Value>, outbounds: &mut Vec<Outbound>) -> R<Vec<ReverseBridge>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let entries = |key: &str| -> R<Vec<(Arc<str>, Arc<str>)>> {
        let Some(list) = value.get(key).filter(|list| !list.is_null()) else {
            return Ok(Vec::new());
        };
        let list = list
            .as_array()
            .ok_or_else(|| format!("reverse.{key} must be an array"))?;
        list.iter()
            .enumerate()
            .map(|(index, entry)| {
                let text = |name: &str| {
                    entry
                        .get(name)
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|text| !text.is_empty())
                        .map(Arc::<str>::from)
                        .ok_or_else(|| format!("reverse.{key}[{index}].{name} is required"))
                };
                Ok((text("tag")?, text("domain")?))
            })
            .collect()
    };
    for (tag, domain) in entries("portals")? {
        if outbounds.iter().any(|outbound| outbound.tag == tag) {
            return Err(format!("reverse portal tag {tag:?} is already an outbound"));
        }
        outbounds.push(Outbound {
            tag,
            protocol: OutboundProtocol::Portal { domain },
            stream: StreamSettings::default(),
            mux: MuxConfig::default(),
        });
    }
    Ok(entries("bridges")?
        .into_iter()
        .map(|(tag, domain)| ReverseBridge {
            tag,
            domain,
            via: None,
        })
        .collect())
}

/// Sections of an Xray configuration that Zray accepts and does not act on.
/// They are named so that a config that relies on one finds out when it is
/// checked, not when a feature it expected is missing.
fn note_unsupported_sections(obj: &serde_json::Map<String, Value>, out: &mut ParseOutput) {
    const UNSUPPORTED: &[(&str, &str)] = &[
        (
            "api",
            "the gRPC API is not served; `zray run --management` is Zray's own",
        ),
        (
            "stats",
            "statistics are always kept; read them through the management API",
        ),
        (
            "metrics",
            "no expvar/pprof endpoint; the management API reports usage",
        ),
        (
            "fakedns",
            "the FakeDNS pool is Zray's own range; its settings are not read",
        ),
        (
            "transport",
            "global transport settings are not read; set them per outbound",
        ),
        (
            "geodata",
            "rule sets are refreshed through `assets`, not on this schedule",
        ),
        ("env", "environment variables are not set from the config"),
    ];
    for (key, why) in UNSUPPORTED {
        if obj.get(*key).is_some_and(|value| !value.is_null()) {
            out.note(*key, format!("accepted, not applied: {why}"));
        }
    }
    if let Some(log) = obj.get("log").and_then(Value::as_object) {
        for key in ["access", "error"] {
            if log
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|path| !path.is_empty() && path != "none")
            {
                out.note(
                    format!("log.{key}"),
                    "accepted, not applied: logs go to standard error, set with ZRAY_LOG",
                );
            }
        }
    }
}

/// Parse and compile one configuration in a single, explicit boundary.
///
/// Keeping this separate from `parse_config` makes it possible for tools to
/// inspect diagnostics without constructing a runtime generation, while the
/// application path cannot accidentally skip validation or id assignment.
pub fn compile_config(
    v: &Value,
    generation: zero_core::GenerationId,
) -> R<(RuntimeGeneration, ParseOutput)> {
    let (config, diagnostics) = parse_config(v)?;
    let generation = RuntimeGeneration::compile(config, generation)?;
    Ok((generation, diagnostics))
}

/// Parse a subscription body that is a JSON array of configs.
pub fn parse_config_array(text: &str) -> R<Vec<(String, RuntimeConfig, ParseOutput)>> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let items: Vec<&Value> = match &v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![&v],
        _ => return Err("expected a config object or array".into()),
    };
    items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            let remark = item
                .get("remarks")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let (cfg, out) =
                parse_config(item).map_err(|e| format!("config[{i}] ({remark}): {e}"))?;
            Ok((remark, cfg, out))
        })
        .collect()
}

// ----------------------------------------------------------------- inbounds

fn parse_inbounds(arr: &[Value], out: &mut ParseOutput) -> R<Vec<Inbound>> {
    let mut inbounds = Vec::new();
    for (i, v) in arr.iter().enumerate() {
        inbounds.extend(parse_inbound_ports(v, i, out)?);
    }
    Ok(inbounds)
}

/// The most ports one inbound may span; a range this wide is a mistake, and
/// each port is a listening socket.
const MAX_INBOUND_PORTS: usize = 1024;

/// One inbound entry as one listener per port: `port` may be a number, a
/// string such as `"443"`, `"20000-20100"` or `"80,443,8000-8010"`. Every
/// listener keeps the entry's tag, as Xray's does, so one rule covers the
/// whole range.
fn parse_inbound_ports(v: &Value, idx: usize, out: &mut ParseOutput) -> R<Vec<Inbound>> {
    let ports = match v.get("port") {
        Some(Value::String(text)) => {
            let ranges: Vec<routing::PortRange> = text
                .split(',')
                .map(|part| {
                    routing::PortRange::parse(part)
                        .filter(|range| range.start <= range.end)
                        .ok_or_else(|| {
                            format!("inbounds[{idx}].port {text:?} is not a port, range or list")
                        })
                })
                .collect::<R<_>>()?;
            let ports: Vec<u16> = ranges.iter().flat_map(|r| r.start..=r.end).collect();
            if ports.len() > MAX_INBOUND_PORTS {
                return Err(format!(
                    "inbounds[{idx}].port spans {} ports; at most {MAX_INBOUND_PORTS}",
                    ports.len()
                ));
            }
            Some(ports)
        }
        _ => None,
    };
    match ports {
        None => Ok(vec![parse_inbound(v, idx, out)?]),
        Some(ports) => ports
            .into_iter()
            .map(|port| {
                let mut single = v.clone();
                single["port"] = Value::from(port);
                parse_inbound(&single, idx, out)
            })
            .collect(),
    }
}

fn parse_inbound(v: &Value, idx: usize, _out: &mut ParseOutput) -> R<Inbound> {
    let path = format!("inbounds[{idx}]");
    let translated;
    let v = if v.get("protocol").and_then(Value::as_str) == Some("hysteria") {
        translated = xray_hysteria_inbound(v, &path)?;
        &translated
    } else {
        v
    };
    let proto = v.get("protocol").and_then(Value::as_str).unwrap_or("");
    let mut protocol = match proto {
        "socks" => InboundProtocol::Socks,
        "http" => InboundProtocol::Http,
        "mixed" => InboundProtocol::Mixed,
        "vless" => InboundProtocol::Vless(parse_vless_inbound(v.get("settings"), &path)?),
        "trojan" => InboundProtocol::Trojan(parse_trojan_inbound(v.get("settings"), &path)?),
        "vmess" => InboundProtocol::Vmess(parse_vmess_inbound(v.get("settings"), &path)?),
        "shadowsocks" => {
            InboundProtocol::Shadowsocks(parse_shadowsocks_inbound(v.get("settings"), &path)?)
        }
        "anytls" => InboundProtocol::AnyTls(parse_anytls_inbound(v.get("settings"), &path)?),
        // "tide" is the name the protocol was built under.
        "zerov1" | "tide" => InboundProtocol::Tide(parse_tide_inbound(v.get("settings"), &path)?),
        "zerov1-relay" => InboundProtocol::TideRelay(parse_tide_relay(v.get("settings"), &path)?),
        "hysteria2" => {
            InboundProtocol::Hysteria2(parse_hysteria2_inbound(v.get("settings"), &path)?)
        }
        "tuic" => InboundProtocol::Tuic(parse_tuic_inbound(v.get("settings"), &path)?),
        "tun" => InboundProtocol::Tun(parse_tun_inbound(v.get("settings"), &path)?),
        "wireguard" => {
            InboundProtocol::WireGuard(parse_wireguard_inbound(v.get("settings"), &path)?)
        }
        "dokodemo-door" => {
            let s = v.get("settings");
            let get = |new: &str, old: &str| {
                s.and_then(|s| s.get(new).or_else(|| s.get(old)))
                    .filter(|value| !value.is_null())
            };
            // `network` is a comma list ("tcp,udp"); absent means TCP.
            let (mut tcp, mut udp) = (false, false);
            let listed = get("allowedNetwork", "network")
                .and_then(Value::as_str)
                .unwrap_or("tcp");
            for name in listed.split(',') {
                match name.trim().to_ascii_lowercase().as_str() {
                    "tcp" => tcp = true,
                    "udp" => udp = true,
                    "" => {}
                    other => {
                        return Err(format!(
                            "{path}.settings.network: {other:?} is not \"tcp\" or \"udp\""
                        ))
                    }
                }
            }
            let mut port_map = Vec::new();
            if let Some(map) = s.and_then(|s| s.get("portMap")).and_then(Value::as_object) {
                for (from, to) in map {
                    let key: u16 = from.trim().parse().map_err(|_| {
                        format!("{path}.settings.portMap: key {from:?} is not a port")
                    })?;
                    let (host, to_port) = to
                        .as_str()
                        .and_then(zero_core::address::split_host_port)
                        .ok_or_else(|| {
                            format!("{path}.settings.portMap[{from}] must be \"host:port\"")
                        })?;
                    port_map.push((key, Address::parse_host(host), to_port));
                }
            }
            InboundProtocol::Dokodemo {
                address: get("rewriteAddress", "address")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                    .map(Address::parse_host),
                port: get("rewritePort", "port")
                    .and_then(json_port)
                    .filter(|port| *port != 0),
                port_map,
                tcp,
                udp,
                follow_redirect: s
                    .and_then(|s| s.get("followRedirect"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }
        }
        "" => {
            // Placeholder / empty inbound or API inbound tag
            InboundProtocol::Dokodemo {
                address: None,
                port: None,
                port_map: Vec::new(),
                tcp: true,
                udp: false,
                follow_redirect: false,
            }
        }
        other => {
            return Err(format!("{path}.protocol: unsupported inbound {other:?}"));
        }
    };

    let mut transport = match v.get("streamSettings") {
        Some(settings) => parse_inbound_transport(settings, &path)?,
        None => Transport::Raw,
    };
    let raw_http_header = v
        .get("streamSettings")
        .map(|settings| parse_raw_http_header(settings, &path))
        .transpose()?
        .flatten();
    if raw_http_header.is_some() && !matches!(transport, Transport::Raw) {
        return Err(format!(
            "{path}.streamSettings.rawSettings.header: HTTP camouflage requires the raw carrier"
        ));
    }
    validate_inbound_transport(&transport, &path)?;
    let mut security = parse_inbound_security(v.get("streamSettings"), &path)?;
    if let Transport::Xhttp(settings) = &mut transport {
        if settings.xhttp_mode == XhttpMode::Auto {
            settings.xhttp_mode = if matches!(&security, InboundSecurity::Reality(_)) {
                if settings.xhttp_download.is_some() {
                    XhttpMode::StreamUp
                } else {
                    XhttpMode::StreamOne
                }
            } else {
                XhttpMode::PacketUp
            };
        }
    }
    if matches!(
        protocol,
        InboundProtocol::AnyTls(_) | InboundProtocol::Hysteria2(_) | InboundProtocol::Tuic(_)
    ) {
        if !matches!(transport, Transport::Raw) {
            return Err(format!(
                "{path}.streamSettings.network: AnyTLS, Hysteria2, and TUIC require the raw carrier"
            ));
        }
        if !matches!(security, InboundSecurity::Tls(_)) {
            return Err(format!(
                "{path}.streamSettings.security: AnyTLS, Hysteria2, and TUIC require certificate TLS"
            ));
        }
    }
    if matches!(
        protocol,
        InboundProtocol::Tide(_) | InboundProtocol::TideRelay(_)
    ) {
        if !matches!(transport, Transport::Raw) {
            return Err(format!(
                "{path}.streamSettings.network: Tide speaks HTTP/2 itself and needs the raw carrier"
            ));
        }
        match &mut security {
            // Tide is HTTP/2 whatever the config says about ALPN.
            InboundSecurity::Tls(tls) => tls.alpn = vec![Box::from("h2")].into_boxed_slice(),
            // REALITY hands over a plain encrypted stream once the client has
            // proved itself, and HTTP/2 runs over that as it does over TLS.
            // The links this server makes carry what the client needs to
            // get through it, so they are told here.
            InboundSecurity::Reality(reality) => {
                if let (InboundProtocol::Tide(tide), Some(name)) =
                    (&mut protocol, reality.server_names.first())
                {
                    tide.reality = Some(TideRealityLink {
                        server_name: name.clone(),
                        private_key: reality.private_key,
                        short_id: reality
                            .short_ids
                            .first()
                            .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect())
                            .unwrap_or_default(),
                    });
                }
            }
            InboundSecurity::None => {}
        }
    }
    if matches!(protocol, InboundProtocol::Tun(_))
        && (!matches!(transport, Transport::Raw) || !matches!(security, InboundSecurity::None))
    {
        return Err(format!(
            "{path}: TUN inbounds cannot use stream transport or security"
        ));
    }
    if let Transport::Xhttp(settings) = &transport {
        if settings.xhttp_http_version == XhttpHttpVersion::Http3
            && !matches!(&security, InboundSecurity::Tls(_))
        {
            return Err(format!(
                "{path}.streamSettings: inbound XHTTP HTTP/3 requires certificate TLS"
            ));
        }
        if settings.xhttp_http_version == XhttpHttpVersion::Http3
            && !matches!(
                settings.xhttp_mode,
                XhttpMode::StreamOne | XhttpMode::StreamUp
            )
        {
            return Err(format!(
                "{path}.streamSettings: inbound XHTTP HTTP/3 supports stream-one or stream-up"
            ));
        }
    }
    if matches!(transport, Transport::Grpc(_)) {
        if let InboundSecurity::Tls(tls) = &mut security {
            if tls.alpn.is_empty() {
                tls.alpn = vec![Box::from("h2")].into_boxed_slice();
            }
        }
    }

    let socks_auth = match proto {
        "socks" | "mixed" => parse_socks_auth(v.get("settings"), &path)?,
        "http" => parse_http_auth(v.get("settings"), &path)?,
        _ => SocksAuth::None,
    };

    let sniffing = v
        .get("sniffing")
        .map(|s| {
            let dests: Vec<&str> = s
                .get("destOverride")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            Sniffing {
                enabled: s.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                sniff_http: dests.contains(&"http"),
                sniff_tls: dests.contains(&"tls"),
                sniff_quic: dests.contains(&"quic"),
                route_only: s.get("routeOnly").and_then(Value::as_bool).unwrap_or(false),
                domains_excluded: s
                    .get("domainsExcluded")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .map(routing::DomainPattern::parse)
                            .collect()
                    })
                    .unwrap_or_default(),
                metadata_only: s
                    .get("metadataOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }
        })
        .unwrap_or_default();

    Ok(Inbound {
        tag: Arc::from(v.get("tag").and_then(Value::as_str).unwrap_or("in")),
        listen: Address::parse_host(
            v.get("listen")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1"),
        ),
        port: match v.get("port").and_then(Value::as_u64) {
            Some(port) if port <= u16::MAX as u64 => port as u16,
            Some(_) => return Err(format!("{path}.port is invalid")),
            None if matches!(protocol, InboundProtocol::Tun(_)) => 0,
            None => return Err(format!("{path}.port is required")),
        },
        protocol,
        transport,
        raw_http_header,
        security,
        sniffing,
        socks_auth,
        sockopt: match v.get("streamSettings").and_then(|s| s.get("sockopt")) {
            Some(sockopt) => parse_sockopt(sockopt, &path)?,
            None => Sockopt::default(),
        },
        accept_proxy_protocol: v
            .get("streamSettings")
            .map(|stream| {
                [
                    stream.get("sockopt"),
                    stream.get("rawSettings"),
                    stream.get("tcpSettings"),
                ]
                .into_iter()
                .flatten()
                .any(|section| {
                    section
                        .get("acceptProxyProtocol")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false),
    })
}

/// An `http` inbound's accounts. Xray's HTTP inbound has no `auth` switch:
/// listing accounts is what turns `Proxy-Authorization` on, so a non-empty
/// `accounts` reads as password auth with the same checks SOCKS applies.
fn parse_http_auth(settings: Option<&Value>, path: &str) -> R<SocksAuth> {
    let listed = settings
        .and_then(|settings| settings.get("accounts"))
        .and_then(Value::as_array)
        .is_some_and(|accounts| !accounts.is_empty());
    if !listed {
        return Ok(SocksAuth::None);
    }
    let mut forced = settings.cloned().unwrap_or_default();
    forced["auth"] = Value::from("password");
    parse_socks_auth(Some(&forced), path)
}

fn parse_socks_auth(settings: Option<&Value>, path: &str) -> R<SocksAuth> {
    let auth = settings
        .and_then(|settings| settings.get("auth"))
        .and_then(Value::as_str)
        .unwrap_or("noauth");
    match auth {
        "noauth" | "none" => Ok(SocksAuth::None),
        "password" => {
            let accounts = settings
                .and_then(|settings| settings.get("accounts"))
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{path}.settings.accounts is required for password auth"))?;
            if accounts.is_empty() {
                return Err(format!(
                    "{path}.settings.accounts must not be empty for password auth"
                ));
            }
            let mut parsed = Vec::with_capacity(accounts.len());
            for (index, account) in accounts.iter().enumerate() {
                let account_path = format!("{path}.settings.accounts[{index}]");
                let username = account
                    .get("user")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{account_path}.user is required"))?;
                let password = account
                    .get("pass")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{account_path}.pass is required"))?;
                if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                    return Err(format!(
                        "{account_path}: user and pass must fit the SOCKS5 auth octets"
                    ));
                }
                parsed.push(SocksAccount {
                    username: username.into(),
                    password: password.into(),
                });
            }
            Ok(SocksAuth::Password(parsed.into_boxed_slice()))
        }
        other => Err(format!(
            "{path}.settings.auth: unsupported SOCKS auth method {other:?}"
        )),
    }
}

fn validate_inbound_transport(transport: &Transport, path: &str) -> R<()> {
    if matches!(
        transport,
        Transport::Raw
            | Transport::WebSocket(_)
            | Transport::HttpUpgrade(_)
            | Transport::Grpc(_)
            | Transport::Xhttp(_)
    ) {
        Ok(())
    } else {
        Err(format!(
            "{path}.streamSettings.network: inbound transport {} is not implemented",
            transport.name()
        ))
    }
}

fn parse_inbound_transport(v: &Value, path: &str) -> R<Transport> {
    match v.get("network").and_then(Value::as_str).unwrap_or("raw") {
        "raw" | "tcp" => Ok(Transport::Raw),
        "ws" => Ok(Transport::WebSocket(parse_ws(v.get("wsSettings")))),
        "httpupgrade" => Ok(Transport::HttpUpgrade(parse_ws(
            v.get("httpupgradeSettings"),
        ))),
        "grpc" => Ok(Transport::Grpc(parse_grpc(v.get("grpcSettings")))),
        "xhttp" | "splithttp" => {
            let config = parse_xhttp(xhttp_settings(v), v, path)?;
            if matches!(
                config.xhttp_http_version,
                XhttpHttpVersion::Http1 | XhttpHttpVersion::Http2
            ) && matches!(
                config.xhttp_mode,
                XhttpMode::Auto | XhttpMode::StreamOne | XhttpMode::StreamUp | XhttpMode::PacketUp
            ) {
                Ok(Transport::Xhttp(config))
            } else if config.xhttp_http_version == XhttpHttpVersion::Http3
                && matches!(
                    config.xhttp_mode,
                    XhttpMode::StreamOne | XhttpMode::StreamUp | XhttpMode::PacketUp
                )
            {
                // Both stream-one and the independent stream-up legs are
                // served by the QUIC listener.
                Ok(Transport::Xhttp(config))
            } else {
                Err(format!(
                    "{path}.streamSettings.network: inbound XHTTP supports HTTP/1, HTTP/2, or HTTP/3 stream-one/stream-up"
                ))
            }
        }
        other => Err(format!(
            "{path}.streamSettings.network: inbound transport {other:?} is not implemented"
        )),
    }
}

fn parse_inbound_security(settings: Option<&Value>, path: &str) -> R<InboundSecurity> {
    let Some(settings) = settings else {
        return Ok(InboundSecurity::None);
    };
    match settings
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none")
    {
        "none" => Ok(InboundSecurity::None),
        "tls" => {
            let tls = settings
                .get("tlsSettings")
                .ok_or_else(|| format!("{path}.streamSettings.tlsSettings is required"))?;
            // Every entry that is a server identity: Xray's default usage is
            // `encipherment`; `verify` and `issue` entries name other things
            // and are not certificates this server presents.
            let mut identities = Vec::new();
            for (index, entry) in tls
                .get("certificates")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                match entry.get("usage").and_then(Value::as_str) {
                    None | Some("encipherment") => {}
                    Some("verify" | "issue") => continue,
                    Some(other) => {
                        return Err(format!(
                            "{path}.streamSettings.tlsSettings.certificates[{index}].usage {other:?} is not known"
                        ))
                    }
                }
                let entry_path = format!("{path}.streamSettings.tlsSettings.certificates[{index}]");
                identities.push((
                    read_certificate_blob(entry, &entry_path)?.into_boxed_slice(),
                    read_key_blob(entry, &entry_path)?.into_boxed_slice(),
                ));
            }
            if identities.is_empty() {
                return Err(format!(
                    "{path}.streamSettings.tlsSettings.certificates is required"
                ));
            }
            let (certificate, private_key) = identities.remove(0);
            let alpn = tls
                .get("alpn")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(Box::from).collect())
                .unwrap_or_default();
            Ok(InboundSecurity::Tls(InboundTlsConfig {
                certificate,
                private_key,
                alpn,
                extra_identities: identities.into_boxed_slice(),
                reject_unknown_sni: tls
                    .get("rejectUnknownSni")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }))
        }
        "reality" => {
            let reality = settings
                .get("realitySettings")
                .ok_or_else(|| format!("{path}.streamSettings.realitySettings is required"))?;
            let private_key = parse_reality_private_key(
                reality
                    .get("privateKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{path}: reality privateKey is required"))?,
            )
            .map_err(|e| format!("{path}: {e}"))?;
            let server_names = reality
                .get("serverNames")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{path}: reality serverNames is required"))?
                .iter()
                .filter_map(Value::as_str)
                .map(Box::from)
                .collect::<Vec<_>>();
            if server_names.is_empty() {
                return Err(format!("{path}: reality serverNames must not be empty"));
            }
            let short_ids = reality
                .get("shortIds")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{path}: reality shortIds is required"))?
                .iter()
                .map(|id| {
                    parse_hex(id.as_str().unwrap_or(""))
                        .map(|bytes| bytes.into_boxed_slice())
                        .map_err(|e| format!("{path}: reality shortId: {e}"))
                })
                .collect::<R<Vec<_>>>()?;
            let target = reality
                .get("dest")
                .or_else(|| reality.get("target"))
                .and_then(Value::as_str)
                .and_then(zero_core::address::split_host_port)
                .map(|(host, port)| (Address::parse_host(host), port));
            let mldsa65_seed = match reality.get("mldsa65Seed").and_then(Value::as_str) {
                None | Some("") => None,
                Some(text) => {
                    use base64::Engine as _;
                    let seed: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(text.trim())
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(|| {
                            format!("{path}: reality mldsa65Seed must be 32 bytes of base64url")
                        })?;
                    Some(Secret32(seed))
                }
            };
            let version = |key: &str| -> R<Option<[u8; 3]>> {
                match reality
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                {
                    None => Ok(None),
                    Some(text) => {
                        let parts: Vec<u8> = text
                            .split('.')
                            .map(|part| part.parse().ok())
                            .collect::<Option<_>>()
                            .filter(|parts: &Vec<u8>| parts.len() == 3)
                            .ok_or_else(|| format!("{path}: reality {key} must look like 1.2.3"))?;
                        Ok(Some([parts[0], parts[1], parts[2]]))
                    }
                }
            };
            let limit = |key: &str| -> R<FallbackLimit> {
                let Some(value) = reality.get(key).filter(|v| !v.is_null()) else {
                    return Ok(FallbackLimit::default());
                };
                let number = |name: &str| {
                    value.get(name).map_or(Ok(0u64), |v| {
                        v.as_u64()
                            .ok_or_else(|| format!("{path}: reality {key}.{name} must be a number"))
                    })
                };
                Ok(FallbackLimit {
                    after_bytes: number("afterBytes")?,
                    bytes_per_sec: number("bytesPerSec")?,
                    burst_bytes_per_sec: number("burstBytesPerSec")?,
                })
            };
            let fallback_xver = match reality.get("xver").and_then(Value::as_u64) {
                None | Some(0) => 0,
                Some(version @ (1 | 2)) => version as u8,
                Some(other) => {
                    return Err(format!(
                        "{path}: reality xver must be 0, 1 or 2, not {other}"
                    ))
                }
            };
            Ok(InboundSecurity::Reality(InboundRealityConfig {
                server_names: server_names.into_boxed_slice(),
                private_key,
                short_ids: short_ids.into_boxed_slice(),
                target,
                mldsa65_seed,
                max_time_diff_ms: reality
                    .get("maxTimeDiff")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                min_client_ver: version("minClientVer")?,
                max_client_ver: version("maxClientVer")?,
                fallback_xver,
                fallback_limit_up: limit("limitFallbackUpload")?,
                fallback_limit_down: limit("limitFallbackDownload")?,
            }))
        }
        other => Err(format!(
            "{path}.streamSettings.security: unsupported inbound security {other:?}"
        )),
    }
}

/// Read `dns.certificates` entries marked `usage: "verify"`.
///
/// Encrypted resolvers verify their server exactly like any other TLS client,
/// so an operator's private CA has to be nameable here too. Without it the
/// only way to reach a self-hosted DoT/DoH/DoQ resolver is to turn
/// verification off, which is the outcome this whole shape exists to avoid.
fn parse_dns_trusted_roots(v: &Value) -> R<Vec<Box<[u8]>>> {
    let Some(entries) = v.get("certificates").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = format!("dns.certificates[{index}]");
        match entry.get("usage").and_then(Value::as_str) {
            Some("verify") => {}
            Some(other) => {
                return Err(format!(
                    "{entry_path}.usage {other:?} is not usable for a resolver; \
                     only \"verify\" adds a trust anchor"
                ))
            }
            None => {
                return Err(format!(
                    "{entry_path}.usage is required and must be \"verify\""
                ))
            }
        }
        let blob = read_certificate_blob(entry, &entry_path)?;
        if blob.is_empty() {
            return Err(format!("{entry_path} is empty"));
        }
        roots.push(blob.into_boxed_slice());
    }
    Ok(roots)
}

/// Read outbound `tlsSettings.certificates` entries marked `usage: "verify"`.
///
/// This is the supported alternative to `allowInsecure`, which the validator
/// refuses. Naming an extra issuer is a bounded, reviewable statement of trust;
/// switching verification off is not, and the difference matters most exactly
/// where these configurations are used.
fn parse_trusted_roots(tls: Option<&Value>, path: &str) -> R<Vec<Box<[u8]>>> {
    let Some(entries) = tls
        .and_then(|tls| tls.get("certificates"))
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = format!("{path}.streamSettings.tlsSettings.certificates[{index}]");
        match entry.get("usage").and_then(Value::as_str) {
            // Xray's default usage is `encipherment`, which is a server-side
            // key pair and meaningless on an outbound.
            Some("verify") => {}
            Some(other) => {
                return Err(format!(
                    "{entry_path}.usage {other:?} is not usable on an outbound; only \"verify\" adds a trust anchor"
                ))
            }
            None => {
                return Err(format!(
                    "{entry_path}.usage is required on an outbound and must be \"verify\""
                ))
            }
        }
        let blob = read_certificate_blob(entry, &entry_path)?;
        if blob.is_empty() {
            return Err(format!("{entry_path} is empty"));
        }
        roots.push(blob.into_boxed_slice());
    }
    Ok(roots)
}

/// An inline certificate or key: Xray writes it as an array of lines (what
/// `xray tls cert` prints), joined by newlines to make the PEM text. One
/// element holding the whole PEM is the same thing.
fn pem_lines(lines: &[Value]) -> Option<Vec<u8>> {
    let lines: Vec<&str> = lines.iter().filter_map(Value::as_str).collect();
    (!lines.is_empty()).then(|| lines.join("\n").into_bytes())
}

fn read_certificate_blob(certificate: &Value, path: &str) -> R<Vec<u8>> {
    if let Some(file) = certificate.get("certificateFile").and_then(Value::as_str) {
        return std::fs::read(file)
            .map_err(|e| format!("{path}: reading certificateFile {file:?}: {e}"));
    }
    if let Some(inline) = certificate.get("certificate").and_then(Value::as_array) {
        return pem_lines(inline).ok_or_else(|| format!("{path}: certificate array is empty"));
    }
    Err(format!(
        "{path}: certificateFile or certificate is required"
    ))
}

fn read_key_blob(certificate: &Value, path: &str) -> R<Vec<u8>> {
    if let Some(file) = certificate.get("keyFile").and_then(Value::as_str) {
        return std::fs::read(file).map_err(|e| format!("{path}: reading keyFile {file:?}: {e}"));
    }
    if let Some(inline) = certificate.get("key").and_then(Value::as_array) {
        return pem_lines(inline).ok_or_else(|| format!("{path}: key array is empty"));
    }
    Err(format!("{path}: keyFile or key is required"))
}

/// A client's `email`, the name Xray's `user` rules and statistics use.
fn client_email(client: &Value) -> Option<Arc<str>> {
    client
        .get("email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(Arc::from)
}

fn parse_vless_inbound(settings: Option<&Value>, path: &str) -> R<VlessInboundConfig> {
    let clients = settings
        .and_then(|s| s.get("clients"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}.settings.clients is required for vless"))?;
    let mut users = Vec::with_capacity(clients.len());
    for (idx, client) in clients.iter().enumerate() {
        let client_path = format!("{path}.settings.clients[{idx}]");
        let uuid = crate::share_link::parse_uuid(
            client
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{client_path}.id is required"))?,
        )
        .map_err(|error| format!("{client_path}.id: {error}"))?;
        let flow_text = client.get("flow").and_then(Value::as_str).unwrap_or("");
        let flow = Flow::parse(flow_text)
            .ok_or_else(|| format!("{client_path}.flow is not supported: {flow_text:?}"))?;
        users.push(VlessInboundUser {
            uuid,
            flow,
            vision_seed: parse_vision_seed(
                client
                    .get("testseed")
                    .or_else(|| settings.and_then(|s| s.get("testseed"))),
                &client_path,
            )?,
            email: client_email(client),
            reverse: client
                .get("reverse")
                .and_then(|reverse| reverse.get("tag"))
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
                .map(Arc::from),
        });
    }
    if users.is_empty() {
        return Err(format!("{path}.settings.clients must not be empty"));
    }
    let decryption = match settings
        .and_then(|s| s.get("decryption"))
        .and_then(Value::as_str)
        .map(str::trim)
    {
        None | Some("") | Some("none") => None,
        Some(value) if value.starts_with("mlkem768x25519plus.") => Some(Arc::<str>::from(value)),
        Some(_) => {
            return Err(format!(
                "{path}.settings.decryption is not \"none\" or a mlkem768x25519plus setting"
            ))
        }
    };
    let fallbacks = parse_fallback(settings, path)?;
    if decryption.is_some() && !fallbacks.is_empty() {
        return Err(format!(
            "{path}.settings: fallbacks cannot be used together with decryption"
        ));
    }
    Ok(VlessInboundConfig {
        users: users.into_boxed_slice(),
        decryption,
        fallbacks,
    })
}

/// The catch-all entry of an inbound's `fallbacks`: where to send a
/// connection that did not authenticate.
///
/// Xray lets a fallback be chosen by TLS name, ALPN or request path; only an
/// entry with none of those conditions is honoured here, and it applies to
/// every failed connection. `dest` is a port on this machine (`80`), or
/// `host:port`. A Unix socket is refused rather than silently ignored, since
/// a fallback that does not work leaves the server recognisable.
fn parse_fallback(settings: Option<&Value>, path: &str) -> R<Box<[FallbackRule]>> {
    let Some(entries) = settings
        .and_then(|s| s.get("fallbacks"))
        .and_then(Value::as_array)
    else {
        return Ok(Box::new([]));
    };
    let mut rules = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let here = format!("{path}.settings.fallbacks[{index}]");
        let text = |key: &str| {
            entry
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(Box::<str>::from)
        };
        let route = text("path");
        if route
            .as_deref()
            .is_some_and(|route| !route.starts_with('/'))
        {
            return Err(format!("{here}.path must start with /"));
        }
        let what = format!("{here}.dest");
        let port = |value: u64| {
            u16::try_from(value)
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| format!("{what} is not a valid port"))
        };
        let dest = match entry.get("dest") {
            Some(Value::Number(number)) => (
                Address::parse_host("127.0.0.1"),
                port(number.as_u64().unwrap_or(0))?,
            ),
            Some(Value::String(text)) if text.starts_with('/') || text.starts_with('@') => {
                return Err(format!(
                    "{what}: Unix socket fallbacks are not supported; use a port"
                ))
            }
            Some(Value::String(text)) => match text.rsplit_once(':') {
                Some((host, number)) => (
                    Address::parse_host(host.trim_matches(|c| c == '[' || c == ']')),
                    port(number.parse().unwrap_or(0))?,
                ),
                None => (
                    Address::parse_host("127.0.0.1"),
                    port(text.parse().unwrap_or(0))?,
                ),
            },
            _ => return Err(format!("{what} is required")),
        };
        let xver = match entry.get("xver").and_then(Value::as_u64) {
            None | Some(0) => 0,
            Some(version @ (1 | 2)) => version as u8,
            Some(other) => return Err(format!("{here}.xver must be 0, 1 or 2, not {other}")),
        };
        rules.push(FallbackRule {
            name: text("name"),
            alpn: text("alpn"),
            path: route,
            dest,
            xver,
        });
    }
    Ok(rules.into_boxed_slice())
}

fn parse_trojan_inbound(settings: Option<&Value>, path: &str) -> R<TrojanInboundConfig> {
    let clients = settings
        .and_then(|s| s.get("clients"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}.settings.clients is required for trojan"))?;
    let mut password_hashes = Vec::with_capacity(clients.len());
    let mut emails = Vec::with_capacity(clients.len());
    for (idx, client) in clients.iter().enumerate() {
        let client_path = format!("{path}.settings.clients[{idx}]");
        let password = client
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{client_path}.password is required"))?;
        password_hashes.push(crate::trojan_hash(password));
        emails.push(client_email(client));
    }
    if password_hashes.is_empty() {
        return Err(format!("{path}.settings.clients must not be empty"));
    }
    Ok(TrojanInboundConfig {
        password_hashes: password_hashes.into_boxed_slice(),
        emails: emails.into_boxed_slice(),
        fallbacks: parse_fallback(settings, path)?,
    })
}

fn parse_vmess_inbound(settings: Option<&Value>, path: &str) -> R<VmessInboundConfig> {
    let clients = settings
        .and_then(|s| s.get("clients"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}.settings.clients is required for vmess"))?;
    let users = clients
        .iter()
        .enumerate()
        .map(|(idx, client)| {
            let client_path = format!("{path}.settings.clients[{idx}]");
            let uuid = crate::share_link::parse_uuid(
                client
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{client_path}.id is required"))?,
            )
            .map_err(|error| format!("{client_path}.id: {error}"))?;
            reject_legacy_alter_id(client, &client_path)?;
            let cipher = VmessCipher::parse(
                client
                    .get("security")
                    .and_then(Value::as_str)
                    .unwrap_or("auto"),
            )
            .ok_or_else(|| format!("{client_path}.security is unsupported"))?;
            Ok(VmessInboundUser {
                uuid,
                cipher,
                email: client_email(client),
            })
        })
        .collect::<R<Vec<_>>>()?;
    if users.is_empty() {
        return Err(format!("{path}.settings.clients must not be empty"));
    }
    Ok(VmessInboundConfig {
        users: users.into_boxed_slice(),
    })
}

fn parse_shadowsocks_inbound(settings: Option<&Value>, path: &str) -> R<ShadowsocksInboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required"))?;
    let method = settings
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.method is required"))
        .and_then(|value| {
            ShadowsocksMethod::parse(value)
                .ok_or_else(|| format!("{path}.settings.method {value:?} is unsupported"))
        })?;
    let password = settings
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required"))?;
    Ok(ShadowsocksInboundConfig {
        method,
        password: password.into(),
    })
}

// ---------------------------------------------------------------- outbounds

fn parse_outbounds(arr: &[Value], out: &mut ParseOutput) -> R<Vec<Outbound>> {
    arr.iter()
        .enumerate()
        .map(|(i, v)| parse_outbound(v, i, out))
        .collect()
}

/// Xray's simplified outbound form: `settings` holds one server's
/// `address`, `port` and account directly,
///
/// ```json
/// {"protocol": "vless", "settings": {"address": "a.example", "port": 443, "id": "..."}}
/// ```
///
/// where the older form wraps them in `vnext[].users[]` (VLESS, VMess) or
/// `servers[]` (Trojan, Shadowsocks). Both mean the same, and a current Xray
/// or panel writes the first. This returns the config rewritten in the nested
/// form the parsers below read; `None` when the settings are already nested
/// or belong to another protocol.
fn unflatten_outbound(v: &Value) -> Option<Value> {
    nested_outbound(v)
}

/// [`unflatten_outbound`] for the apps that read Xray outbounds themselves
/// (subscription import, sharing a stored profile): the same rewrite, so they
/// see one shape however the outbound was written.
pub fn nested_outbound(v: &Value) -> Option<Value> {
    let protocol = v.get("protocol").and_then(Value::as_str)?;
    let settings = v.get("settings").and_then(Value::as_object)?;
    if settings.contains_key("vnext") || settings.contains_key("servers") {
        return None;
    }
    let address = settings.get("address")?.clone();
    let mut nested = settings.clone();
    let mut server = serde_json::Map::new();
    server.insert("address".into(), address);
    nested.remove("address");
    if let Some(port) = nested.remove("port") {
        server.insert("port".into(), port);
    }
    let settings = match protocol {
        // The account is everything left that belongs to one user; the
        // outbound-wide `testseed` stays where the parser looks for it too.
        "vless" | "vmess" => {
            server.insert(
                "users".into(),
                Value::Array(vec![Value::Object(nested.clone())]),
            );
            nested.retain(|key, _| key == "testseed" || key == "mux");
            nested.insert("vnext".into(), Value::Array(vec![Value::Object(server)]));
            nested
        }
        "trojan" | "shadowsocks" => {
            server.extend(nested);
            let mut settings = serde_json::Map::new();
            settings.insert("servers".into(), Value::Array(vec![Value::Object(server)]));
            settings
        }
        _ => return None,
    };
    let mut flat = v.clone();
    flat["settings"] = Value::Object(settings);
    Some(flat)
}

fn parse_outbound(v: &Value, idx: usize, out: &mut ParseOutput) -> R<Outbound> {
    let path = format!("outbounds[{idx}]");
    let translated;
    let v = if v.get("protocol").and_then(Value::as_str) == Some("hysteria") {
        translated = xray_hysteria_outbound(v, &path)?;
        &translated
    } else {
        v
    };
    let unflattened;
    let v = match unflatten_outbound(v) {
        Some(nested) => {
            unflattened = nested;
            &unflattened
        }
        None => v,
    };
    let tag: Arc<str> = Arc::from(v.get("tag").and_then(Value::as_str).unwrap_or("out"));

    // A Zray extension: an outbound may be written as the share link it came
    // from. Every Iranian user imports configuration as a link, and re-encoding
    // one into an `outbounds` object by hand is where transport and security
    // details get lost. Delegating to the link parser keeps exactly one
    // implementation of that mapping.
    if let Some(link) = v.get("link").and_then(Value::as_str) {
        if v.get("protocol").is_some() {
            return Err(format!("{path} sets both `link` and `protocol`"));
        }
        let parsed = crate::share_link::parse_link(link)
            .map_err(|error| format!("{path}.link is not a usable share link: {error}"))?;
        let mut outbound = parsed.outbound;
        if v.get("tag").is_some() {
            outbound.tag = tag;
        }
        if let Some(mux) = v.get("mux") {
            outbound.mux = parse_mux(Some(mux), &path)?;
        }
        // How XHTTP reuses its connections is this network's business as
        // much as the server's: the app turns it off or on per variant.
        // Nothing to do for another transport.
        if let Some(xmux) = v.get("xmux") {
            if let crate::model::Transport::Xhttp(xhttp) = &mut outbound.stream.transport {
                xhttp.xhttp.xmux = xhttp
                    .xhttp
                    .xmux
                    .overlay(xmux)
                    .map_err(|error| format!("{path}.{error}"))?;
            }
        }
        // A share link cannot carry a sockopt either — it describes the
        // server, not how this machine should dial it. Same reason as
        // `evasion` above: layer the one key that matters on without
        // re-describing the whole outbound, or a congestion-control setting
        // would silently apply only to profiles stored as expanded JSON.
        if let Some(congestion) = v
            .get("streamSettings")
            .and_then(|stream| stream.get("sockopt"))
            .and_then(|sockopt| sockopt.get("tcpCongestion"))
            .and_then(Value::as_str)
        {
            let congestion = congestion.trim();
            if !congestion.is_empty() {
                outbound.stream.sockopt.tcp_congestion = Some(Arc::from(congestion));
            }
        }
        // Which outbound carries the connection to the server is how this
        // machine reaches it, not a property of the server: a link cannot say
        // it. Layered on, so a server found in a feed can be dialled through
        // a WARP tunnel without re-describing it.
        if let Some(via) = v
            .get("streamSettings")
            .and_then(|stream| stream.get("sockopt"))
            .and_then(|sockopt| sockopt.get("dialerProxy"))
            .and_then(Value::as_str)
        {
            let via = via.trim();
            if !via.is_empty() {
                outbound.stream.sockopt.dialer_proxy = Some(Arc::from(via));
            }
        }
        // ECH is the same kind of thing: whether this network needs the name
        // hidden is not the server's to say. `true` asks for it (the list is
        // looked up when the outbound is dialled), `false` drops what the
        // link asked for, so one link can be tried both ways.
        if let Some(on) = v.get("ech").and_then(Value::as_bool) {
            let crate::model::Security::Tls(tls) = &mut outbound.stream.security else {
                return Err(format!("{path}.ech needs certificate TLS"));
            };
            tls.ech = on.then(|| {
                tls.ech.take().unwrap_or(EchConfig {
                    config_list: Box::new([]),
                    server_name: None,
                    query_name: None,
                })
            });
        }
        // The user's own switch to skip certificate checks ("Allow insecure"
        // in the apps), layered over every link at once. Only `true` does
        // anything: absent or `false` leaves the link as it was written, so
        // a link that asked for it itself keeps asking. A carrier without
        // certificate TLS (REALITY, plain, WARP) has no certificate to skip,
        // so it is left alone rather than refused.
        if v.get("allowInsecure").and_then(Value::as_bool) == Some(true) {
            if let crate::model::Security::Tls(tls) = &mut outbound.stream.security {
                tls.allow_insecure = true;
            }
        }
        // A different port on the same server, for a network that cuts one
        // port and not another (Cloudflare answers on 443, 2053, 8443 ...).
        if let Some(port) = v.get("port").and_then(Value::as_u64) {
            let port = u16::try_from(port)
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| format!("{path}.port must be 1..=65535"))?;
            if !outbound.set_port(port) {
                return Err(format!("{path}.port needs a TCP protocol link"));
            }
        }
        // `finalmask: null` takes off the fragmentation the link asked for
        // (`fm=`), so one link can be tried with and without it. It comes
        // first: what is layered on below is meant to stay.
        if v.get("finalmask").is_some_and(Value::is_null) {
            outbound.stream.evasion.tcp_fragment = None;
            outbound.stream.evasion.tcp_fragment_under = None;
        }
        // Evasion is the one thing a link cannot express, because it is a
        // property of this network rather than of the server. Allow it to be
        // layered on without re-describing the whole outbound.
        layer_evasion(&mut outbound.stream.evasion, v.get("evasion"), &path)?;
        // The same in Xray's current spelling, as recipes are passed around:
        // a `finalmask` object with one or two stacked fragment masks.
        if let Some(mask) = v.get("finalmask").filter(|mask| !mask.is_null()) {
            let overlay = parse_finalmask(mask, &path)?;
            if overlay.tcp_fragment.is_some() {
                outbound.stream.evasion.tcp_fragment = overlay.tcp_fragment;
                outbound.stream.evasion.tcp_fragment_under = overlay.tcp_fragment_under;
            }
        }
        outbound.validate()?;
        return Ok(outbound);
    }

    let proto = v.get("protocol").and_then(Value::as_str).unwrap_or("");
    let settings = v.get("settings");

    let protocol = match proto {
        "freedom" => OutboundProtocol::Freedom {
            domain_strategy: parse_freedom_domain_strategy(settings, &path)?,
        },
        "blackhole" => OutboundProtocol::Blackhole {
            response: parse_blackhole_response(settings, &path)?,
        },
        "dns" => OutboundProtocol::Dns {
            rules: parse_dns_outbound_rules(settings, &path)?,
        },
        "loopback" => OutboundProtocol::Loopback {
            inbound_tag: settings
                .and_then(|s| s.get("inboundTag"))
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
                .map(Arc::from)
                .ok_or_else(|| format!("{path}.settings.inboundTag is required for loopback"))?,
        },
        "vless" => parse_vless(settings, &path)?,
        "trojan" => parse_trojan(settings, &path)?,
        "shadowsocks" => parse_shadowsocks(settings, &path)?,
        "vmess" => parse_vmess(settings, &path)?,
        "anytls" => parse_anytls(settings, &path)?,
        "socks" => parse_socks(settings, &path)?,
        "http" => parse_http_upstream(settings, &path)?,
        "tor" => parse_tor(settings, &path)?,
        "zerov1" | "tide" => parse_tide(settings, &path)?,
        "hysteria2" => parse_hysteria2(settings, &path)?,
        "tuic" => parse_tuic(settings, &path)?,
        "juicity" => parse_juicity(settings, &path)?,
        "wireguard" | "amnezia-wg" | "amneziawg" => parse_amnezia_wireguard(settings, &path)?,
        "warp" | "masque" => parse_warp(settings, &path)?,
        "" => {
            // Empty outbound protocol placeholder often generated by clients like Qv2ray for dummy proxy node
            OutboundProtocol::Blackhole { response: None }
        }
        other => {
            return Err(format!("{path}.protocol: unsupported outbound {other:?}"));
        }
    };

    let mux = parse_mux(v.get("mux"), &path)?;

    let mut stream = match v.get("streamSettings") {
        Some(s) => parse_stream(s, &path, out)?,
        None => StreamSettings::default(),
    };
    if let OutboundProtocol::Freedom { domain_strategy } = &protocol {
        // Xray 26.x moved this setting to `streamSettings.sockopt` while
        // retaining `freedom.domainStrategy` as a compatibility alias.  They
        // name one decision, so accepting two contradictory values would
        // produce a configuration that no operator can reason about.
        if *domain_strategy != DomainStrategy::AsIs
            && stream.sockopt.domain_strategy != DomainStrategy::AsIs
            && *domain_strategy != stream.sockopt.domain_strategy
        {
            return Err(format!(
                "{path}: freedom targetStrategy/domainStrategy conflicts with streamSettings.sockopt.domainStrategy"
            ));
        }
        if stream.sockopt.domain_strategy == DomainStrategy::AsIs {
            stream.sockopt.domain_strategy = *domain_strategy;
        }
    }
    if matches!(&protocol, OutboundProtocol::Freedom { .. }) {
        stream.direct = parse_direct_policy(settings, &path)?;
        let legacy = parse_legacy_freedom_evasion(settings, &path)?;
        if !legacy.is_empty() {
            if !stream.evasion.is_empty() {
                return Err(format!(
                    "{path}: freedom evasion must be specified in either settings.fragment/noises or streamSettings.finalmask, not both"
                ));
            }
            stream.evasion = legacy;
        }
    }
    // The same overlay a link outbound takes, so a hand-written outbound can
    // ask for it too (`{"evasion": {"sniSpoof": {"method": "urgent"}}}`).
    layer_evasion(&mut stream.evasion, v.get("evasion"), &path)?;

    // Hysteria 2 has Salamander of its own; Xray writes it as a `finalmask`
    // UDP mask on the connection. Both spellings reach the one setting.
    let mut protocol = protocol;
    if let OutboundProtocol::Hysteria2(hysteria) = &mut protocol {
        if hysteria.obfs_password.is_none() {
            hysteria.obfs_password = stream.evasion.udp_salamander.clone();
        }
    }

    stream.sockopt.bind_address = parse_send_through(v, &path)?;
    let ob = Outbound {
        tag,
        protocol,
        stream,
        mux,
    };
    ob.validate()?;
    Ok(ob)
}

/// An outbound's `sendThrough`: the local address to leave from. Xray also
/// accepts `"origin"` (leave from the address the client reached us on),
/// which Zray cannot know per connection, and an empty or unspecified
/// address, which both mean the system's choice.
fn parse_send_through(v: &Value, path: &str) -> R<Option<std::net::IpAddr>> {
    let Some(text) = v.get("sendThrough").and_then(Value::as_str).map(str::trim) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    if text.eq_ignore_ascii_case("origin") {
        return Err(format!(
            "{path}.sendThrough \"origin\" is not supported; name the address to leave from"
        ));
    }
    let ip: std::net::IpAddr = text
        .parse()
        .map_err(|_| format!("{path}.sendThrough {text:?} is not an IP address"))?;
    Ok((!ip.is_unspecified()).then_some(ip))
}

/// Freedom's `redirect`, `proxyProtocol` and `finalRules`.
///
/// `redirect` is `"host:port"`, `":port"` (only the port) or `"host"` (only
/// the address). `finalRules` entries need an `action`; their `ip` lists may
/// hold CIDR ranges and `geoip:private`, nothing else (a country list needs
/// geodata that is not at hand where the connection is made, and a rule that
/// silently matched nothing would let through what it was written to stop).
fn parse_direct_policy(settings: Option<&Value>, path: &str) -> R<Option<Arc<DirectPolicy>>> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let mut policy = DirectPolicy::default();
    if let Some(text) = settings
        .get("redirect")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        let (host, port) = match zero_core::address::split_host_port(text) {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => match text.strip_prefix(':') {
                Some(port) => (String::new(), port.parse::<u16>().ok()),
                None => (text.to_string(), None),
            },
        };
        if port.is_none() && text.contains(':') && host.is_empty() {
            return Err(format!(
                "{path}.settings.redirect {text:?} is not host:port"
            ));
        }
        policy.redirect = Some(DirectRedirect {
            address: (!host.is_empty()).then(|| Address::parse_host(&host)),
            port,
        });
    }
    match settings.get("proxyProtocol").and_then(Value::as_u64) {
        None | Some(0) => {}
        Some(version @ (1 | 2)) => policy.proxy_protocol = version as u8,
        Some(other) => {
            return Err(format!(
                "{path}.settings.proxyProtocol must be 0, 1 or 2, not {other}"
            ))
        }
    }
    if let Some(rules) = settings.get("finalRules").and_then(Value::as_array) {
        let mut parsed = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            let here = format!("{path}.settings.finalRules[{index}]");
            let allow = match rule.get("action").and_then(Value::as_str) {
                Some("allow") => true,
                Some("block") => false,
                _ => return Err(format!("{here}.action must be \"allow\" or \"block\"")),
            };
            let networks = match rule.get("network").and_then(Value::as_str) {
                None | Some("") => Vec::new(),
                Some(text) => text
                    .split(',')
                    .map(|name| match name.trim() {
                        "tcp" => Ok(Network::Tcp),
                        "udp" => Ok(Network::Udp),
                        other => Err(format!("{here}.network: unknown network {other:?}")),
                    })
                    .collect::<R<_>>()?,
            };
            let ports = rule.get("port").map(parse_port_list).unwrap_or_default();
            if rule.get("port").is_some_and(|p| !p.is_null()) && ports.is_empty() {
                return Err(format!("{here}.port is not a port or range"));
            }
            let mut ips = Vec::new();
            for entry in rule
                .get("ip")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                match parse_ip_pattern(entry) {
                    routing::IpPattern::Geoip(tag) if &*tag != "private" => {
                        return Err(format!(
                            "{here}.ip: geoip:{tag} is not supported in finalRules; list CIDR ranges or use geoip:private"
                        ))
                    }
                    pattern => ips.push(pattern),
                }
            }
            let block_delay_secs = match rule.get("blockDelay") {
                None | Some(Value::Null) => (30, 90),
                Some(value) => parse_secs_range(value, 0, &format!("{here}.blockDelay"))?,
            };
            parsed.push(FinalRule {
                allow,
                networks,
                ports,
                ips,
                block_delay_secs,
            });
        }
        policy.final_rules = parsed.into_boxed_slice();
    }
    Ok((policy != DirectPolicy::default()).then(|| Arc::new(policy)))
}

/// Parse Freedom's destination-resolution policy without treating an explicit
/// unknown value as the default.  Xray accepts the new `targetStrategy` name
/// and its deprecated `domainStrategy` alias; the two must agree when both
/// occur in an imported configuration.
fn parse_freedom_domain_strategy(settings: Option<&Value>, path: &str) -> R<DomainStrategy> {
    let Some(settings) = settings else {
        return Ok(DomainStrategy::AsIs);
    };
    let parse = |field: &str| -> R<Option<DomainStrategy>> {
        let Some(value) = settings.get(field) else {
            return Ok(None);
        };
        let value = value
            .as_str()
            .ok_or_else(|| format!("{path}.settings.{field} must be a string"))?;
        DomainStrategy::parse(value)
            .ok_or_else(|| {
                format!("{path}.settings.{field} has unsupported domain strategy {value:?}")
            })
            .map(Some)
    };

    let target = parse("targetStrategy")?;
    let legacy = parse("domainStrategy")?;
    match (target, legacy) {
        (Some(target), Some(legacy)) if target != legacy => Err(format!(
            "{path}.settings.targetStrategy conflicts with deprecated domainStrategy"
        )),
        (Some(strategy), _) | (_, Some(strategy)) => Ok(strategy),
        (None, None) => Ok(DomainStrategy::AsIs),
    }
}

fn parse_mux(value: Option<&Value>, path: &str) -> R<MuxConfig> {
    let Some(value) = value else {
        return Ok(MuxConfig::default());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path}.mux must be an object"))?;
    let enabled = object
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_concurrency = object
        .get("concurrency")
        .or_else(|| object.get("maxConcurrency"))
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value <= u16::MAX as u64)
                .map(|value| value as u16)
                .ok_or_else(|| format!("{path}.mux.concurrency is invalid"))
        })
        .transpose()?
        .unwrap_or(0);
    let udp443 = match object
        .get("xudpProxyUDP443")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "" | "reject" => Udp443::Reject,
        "allow" => Udp443::Allow,
        "skip" => Udp443::Skip,
        other => return Err(format!("{path}.mux.xudpProxyUDP443 {other:?} is unknown")),
    };
    Ok(MuxConfig {
        enabled,
        max_concurrency,
        udp443,
    })
}

/// Xray's `testseed`: four numbers that size Vision's padding. Fewer than
/// four are ignored by Xray (the defaults apply); anything else is an error
/// here, so a typo does not quietly turn the padding off.
fn parse_vision_seed(value: Option<&Value>, path: &str) -> R<Option<[u32; 4]>> {
    let Some(Value::Array(items)) = value else {
        return Ok(None);
    };
    if items.len() < 4 {
        return Ok(None);
    }
    let mut seed = [0u32; 4];
    for (slot, item) in seed.iter_mut().zip(items) {
        *slot = item
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("{path}.testseed must be four non-negative numbers"))?;
    }
    Ok(Some(seed))
}

fn parse_vless(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let vnext = settings
        .and_then(|s| s.get("vnext"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.vnext is required for vless"))?;

    let user = vnext
        .get("users")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.vnext[0].users is required"))?;

    let flow_str = user.get("flow").and_then(Value::as_str).unwrap_or("");
    let flow = Flow::parse(flow_str).ok_or_else(|| format!("{path}: unknown flow {flow_str:?}"))?;
    // The seed names the padding this end adds: the account's own, or else
    // the one set for the whole outbound.
    let vision_seed = parse_vision_seed(
        user.get("testseed")
            .or_else(|| settings.and_then(|s| s.get("testseed"))),
        &format!("{path}.settings"),
    )?;

    Ok(OutboundProtocol::Vless(VlessConfig {
        address: Address::parse_host(
            vnext
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.vnext[0].address is required"))?,
        ),
        port: vnext
            .get("port")
            .and_then(json_port)
            .ok_or_else(|| format!("{path}.settings.vnext[0].port is required (1-65535)"))?,
        uuid: crate::share_link::parse_uuid(
            user.get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}: user id is required"))?,
        )
        .map_err(|e| format!("{path}: {e}"))?,
        flow,
        vision_seed,
        encryption: user
            .get("encryption")
            .and_then(Value::as_str)
            .unwrap_or("none")
            .into(),
    }))
}

fn parse_trojan(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let server = settings
        .and_then(|s| s.get("servers"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.servers is required for trojan"))?;

    Ok(OutboundProtocol::Trojan(TrojanConfig {
        address: Address::parse_host(
            server
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.servers[0].address is required"))?,
        ),
        port: server
            .get("port")
            .and_then(json_port)
            .ok_or_else(|| format!("{path}.settings.servers[0].port is required (1-65535)"))?,
        password_hash: crate::trojan_hash(
            server
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.servers[0].password is required"))?,
        ),
    }))
}

fn parse_shadowsocks(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let server = settings
        .and_then(|s| s.get("servers"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.servers is required for shadowsocks"))?;
    let method = server
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.servers[0].method is required"))
        .and_then(|value| {
            ShadowsocksMethod::parse(value).ok_or_else(|| {
                format!("{path}.settings.servers[0].method {value:?} is unsupported")
            })
        })?;
    let password = server
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{path}.settings.servers[0].password is required"))?;
    Ok(OutboundProtocol::Shadowsocks(ShadowsocksConfig {
        address: Address::parse_host(
            server
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.servers[0].address is required"))?,
        ),
        port: server
            .get("port")
            .and_then(json_port)
            .ok_or_else(|| format!("{path}.settings.servers[0].port is required (1-65535)"))?,
        method,
        password: password.into(),
    }))
}

/// A nonzero VMess `alterId` selects the legacy MD5-based user hashing that
/// Xray removed in 2022 and this core never implemented. Rather than silently
/// treating the user as AEAD (which fails opaquely at the first frame), reject
/// it at parse time with an actionable message. Absent or zero is fine.
fn reject_legacy_alter_id(user: &Value, path: &str) -> R<()> {
    let alter_id = user
        .get("alterId")
        .or_else(|| user.get("aid"))
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(0);
    if alter_id != 0 {
        return Err(format!(
            "{path}.alterId {alter_id} selects legacy VMess MD5 auth, which is not supported; set alterId to 0 (AEAD)"
        ));
    }
    Ok(())
}

fn parse_vmess(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let server = settings
        .and_then(|s| s.get("vnext"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.vnext is required for vmess"))?;
    let user = server
        .get("users")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("{path}.settings.vnext[0].users is required for vmess"))?;
    reject_legacy_alter_id(user, &format!("{path}.settings.vnext[0].users[0]"))?;
    let cipher = VmessCipher::parse(
        user.get("security")
            .and_then(Value::as_str)
            .unwrap_or("auto"),
    )
    .ok_or_else(|| format!("{path}.settings.vnext[0].users[0].security is unsupported"))?;
    Ok(OutboundProtocol::Vmess(VmessConfig {
        address: Address::parse_host(
            server
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.vnext[0].address is required"))?,
        ),
        port: server
            .get("port")
            .and_then(json_port)
            .ok_or_else(|| format!("{path}.settings.vnext[0].port is required (1-65535)"))?,
        uuid: crate::share_link::parse_uuid(
            user.get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}.settings.vnext[0].users[0].id is required"))?,
        )
        .map_err(|error| format!("{path}.settings.vnext[0].users[0].id: {error}"))?,
        cipher,
    }))
}

fn parse_anytls(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let server = settings
        .and_then(|s| s.get("servers"))
        .and_then(Value::as_array)
        .and_then(|servers| servers.first());
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for anytls"))?;
    let address = server
        .and_then(|s| s.get("address"))
        .or_else(|| settings.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.address is required for anytls"))?;
    let port = server
        .and_then(|s| s.get("port"))
        .or_else(|| settings.get("port"))
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for anytls"))?
        as u16;
    let password = server
        .and_then(|s| s.get("password"))
        .or_else(|| settings.get("password"))
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required for anytls"))?;
    Ok(OutboundProtocol::AnyTls(AnyTlsConfig {
        address: Address::parse_host(address),
        port,
        password: password.into(),
    }))
}

/// Xray's `socks` outbound: `servers[0]` with `address`, `port` and an
/// optional `users[0]` (`user`, `pass`). Xray 26's flat form
/// (`settings.address/port/user/pass`) is accepted as well.
fn parse_socks(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    parse_upstream(settings, path, false)
}

/// Xray's `http` outbound, the same shape as `socks` but spoken to with HTTP
/// `CONNECT`.
fn parse_http_upstream(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    parse_upstream(settings, path, true)
}

fn parse_upstream(settings: Option<&Value>, path: &str, http: bool) -> R<OutboundProtocol> {
    let kind = if http { "http" } else { "socks" };
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for {kind}"))?;
    let server = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .unwrap_or(settings);
    let address = server
        .get("address")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| format!("{path}.settings.address is required for {kind}"))?;
    let port = server
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for {kind}"))?
        as u16;
    let user = server
        .get("users")
        .and_then(Value::as_array)
        .and_then(|users| users.first())
        .unwrap_or(server);
    let text = |key: &str| {
        user.get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let auth = match (text("user"), text("pass")) {
        (None, None) => None,
        (Some(username), Some(password)) => Some(SocksCredential {
            username: username.into(),
            password: password.into(),
        }),
        _ => return Err(format!("{path}.settings: {kind} needs both user and pass")),
    };
    Ok(OutboundProtocol::Socks(SocksConfig {
        address: Address::parse_host(address),
        port,
        auth,
        http,
    }))
}

/// `{"protocol": "tor", "settings": {...}}`. Every field is optional:
/// `bridges` (bridge lines), `transports` (`{"obfs4": "/path/to/lyrebird"}`),
/// `dataDir` and `memoryMiB`.
fn parse_tor(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let Some(settings) = settings else {
        return Ok(OutboundProtocol::Tor(TorConfig::default()));
    };
    let bridges = match settings.get("bridges") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(lines)) => lines
            .iter()
            .map(|line| {
                line.as_str()
                    .map(Box::from)
                    .ok_or_else(|| format!("{path}.settings.bridges must be strings"))
            })
            .collect::<R<Vec<Box<str>>>>()?,
        Some(_) => return Err(format!("{path}.settings.bridges must be an array")),
    };
    let transports = match settings.get("transports") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, program)| {
                program
                    .as_str()
                    .map(|program| (Box::from(name.as_str()), Box::from(program)))
                    .ok_or_else(|| format!("{path}.settings.transports.{name} must be a path"))
            })
            .collect::<R<Vec<_>>>()?,
        Some(_) => return Err(format!("{path}.settings.transports must be an object")),
    };
    let memory_mib = match settings.get("memoryMiB") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .filter(|mib| *mib <= u32::MAX as u64)
            .ok_or_else(|| format!("{path}.settings.memoryMiB must be a number"))?
            as u32,
    };
    Ok(OutboundProtocol::Tor(TorConfig {
        bridges,
        transports,
        data_dir: settings
            .get("dataDir")
            .and_then(Value::as_str)
            .filter(|dir| !dir.is_empty())
            .map(Box::from),
        memory_mib,
    }))
}

/// A Tide key or user id: unpadded URL-safe base64 of exactly `N` bytes.
fn tide_key<const N: usize>(value: Option<&Value>, what: &str) -> R<[u8; N]> {
    use base64::Engine as _;
    value
        .and_then(Value::as_str)
        .and_then(|text| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text.trim())
                .ok()
        })
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what} must be {N} bytes of URL-safe base64"))
}

/// A Tide path prefix: starts with a slash, does not end with one, and has
/// only characters that need no escaping in a request path.
fn tide_path(value: Option<&Value>, what: &str) -> R<Box<str>> {
    let path = value.and_then(Value::as_str).unwrap_or("");
    let plain = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if path.len() < 2 || !path.starts_with('/') || path.ends_with('/') || !plain {
        return Err(format!(
            "{what} must look like \"/some/path\": a leading slash, no trailing one"
        ));
    }
    Ok(path.into())
}

fn parse_tide(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for tide"))?;
    let address = settings
        .get("address")
        .and_then(Value::as_str)
        .filter(|address| !address.is_empty())
        .ok_or_else(|| format!("{path}.settings.address is required for tide"))?;
    let port = settings
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for tide"))? as u16;
    Ok(OutboundProtocol::Tide(TideConfig {
        address: Address::parse_host(address),
        port,
        path: tide_path(settings.get("path"), &format!("{path}.settings.path"))?,
        server_key: tide_key(
            settings.get("serverKey"),
            &format!("{path}.settings.serverKey"),
        )?,
        user: tide_key(settings.get("user"), &format!("{path}.settings.user"))?,
        split: settings
            .get("split")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        packet_upload: settings.get("upload").and_then(Value::as_str) == Some("packet"),
        datagrams: settings
            .get("datagrams")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        rotate: settings
            .get("rotate")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        tuning: TideTuning::parse(&|key| match settings.get(key)? {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            // Headers read naturally as an object in JSON.
            Value::Object(map) if key == "headers" => Some(
                map.iter()
                    .filter_map(|(name, value)| Some(format!("{name}:{}", value.as_str()?)))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            _ => None,
        })
        .map_err(|error| format!("{path}.settings: {error}"))?,
    }))
}

fn parse_tide_inbound(settings: Option<&Value>, path: &str) -> R<TideInboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for tide"))?;
    let mut users = Vec::new();
    for (index, user) in settings
        .get("users")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        users.push(TideUser {
            id: tide_key(
                user.get("id"),
                &format!("{path}.settings.users[{index}].id"),
            )?,
            name: user
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        });
    }
    let text = |key: &str| {
        settings
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(Box::<str>::from)
    };
    let admin_path = match settings.get("adminPath") {
        None | Some(Value::Null) => None,
        some => Some(tide_path(some, &format!("{path}.settings.adminPath"))?),
    };
    Ok(TideInboundConfig {
        path: tide_path(settings.get("path"), &format!("{path}.settings.path"))?,
        secret: tide_key(
            settings.get("secretKey"),
            &format!("{path}.settings.secretKey"),
        )?,
        users: users.into_boxed_slice(),
        users_file: text("usersFile"),
        public_host: text("publicHost"),
        public_port: settings
            .get("publicPort")
            .and_then(Value::as_u64)
            .filter(|port| *port > 0 && *port <= u16::MAX as u64)
            .unwrap_or(443) as u16,
        admin_path,
        shape: match settings.get("shape").and_then(Value::as_str) {
            None => TideShape::default(),
            Some(text) => TideShape::parse(text)
                .ok_or_else(|| format!("{path}.settings.shape must be off, light or full"))?,
        },
        reality: None,
    })
}

fn parse_tide_relay(settings: Option<&Value>, path: &str) -> R<TideRelayConfig> {
    let settings =
        settings.ok_or_else(|| format!("{path}.settings is required for zerov1-relay"))?;
    let upstream = settings
        .get("upstream")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.upstream (host:port) is required"))?;
    let (host, port) = upstream
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host.trim_matches(['[', ']']), port.parse::<u16>().ok()?)))
        .filter(|(host, port)| !host.is_empty() && *port > 0)
        .ok_or_else(|| format!("{path}.settings.upstream must look like host:port"))?;
    Ok(TideRelayConfig {
        path: tide_path(settings.get("path"), &format!("{path}.settings.path"))?,
        upstream_address: Address::parse_host(host),
        upstream_port: port,
        upstream_name: settings
            .get("upstreamName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .map(Box::from),
        upstream_roots: parse_trusted_roots(settings.get("tlsSettings"), path)?,
    })
}

fn parse_anytls_inbound(settings: Option<&Value>, path: &str) -> R<AnyTlsInboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for anytls"))?;
    let mut passwords = Vec::new();
    if let Some(password) = settings.get("password").and_then(Value::as_str) {
        if password.is_empty() {
            return Err(format!("{path}.settings.password must not be empty"));
        }
        passwords.push(Box::<str>::from(password));
    }
    if let Some(users) = settings.get("users").and_then(Value::as_array) {
        for (index, user) in users.iter().enumerate() {
            let password = user
                .get("password")
                .and_then(Value::as_str)
                .filter(|password| !password.is_empty())
                .ok_or_else(|| format!("{path}.settings.users[{index}].password is required"))?;
            passwords.push(password.into());
        }
    }
    if passwords.is_empty() {
        return Err(format!(
            "{path}.settings.password or settings.users is required for anytls"
        ));
    }
    Ok(AnyTlsInboundConfig {
        passwords: passwords.into_boxed_slice(),
    })
}

/// Xray's `hysteria` outbound as the Hysteria 2 outbound Zray has. Xray
/// splits the protocol across three places: the server and version in
/// `settings`, the password as `hysteriaSettings.auth` of the `hysteria`
/// transport, and the Salamander obfuscation as a `finalmask` UDP mask. They
/// are brought together here, so the rest of the parser sees one Hysteria 2
/// outbound with TLS.
fn xray_hysteria_outbound(v: &Value, path: &str) -> R<Value> {
    let settings = v
        .get("settings")
        .ok_or_else(|| format!("{path}.settings is required for hysteria"))?;
    hysteria_version_check(settings, path)?;
    let stream = v.get("streamSettings");
    let auth = stream
        .and_then(|s| s.get("hysteriaSettings"))
        .and_then(|h| h.get("auth"))
        .or_else(|| settings.get("auth"))
        .or_else(|| settings.get("password"))
        .and_then(Value::as_str)
        .filter(|auth| !auth.is_empty())
        .ok_or_else(|| {
            format!("{path}.streamSettings.hysteriaSettings.auth is required for hysteria")
        })?;
    let mut translated = v.clone();
    translated["protocol"] = Value::from("hysteria2");
    let mut new_settings = settings.clone();
    new_settings["password"] = Value::from(auth);
    translated["settings"] = new_settings;
    hysteria_transport_to_raw(&mut translated);
    Ok(translated)
}

/// Xray's `hysteria` inbound as Zray's Hysteria 2 inbound: the users' `auth`
/// strings are the passwords, the transport is plain QUIC with certificate
/// TLS, and a Salamander `finalmask` UDP mask becomes the `obfs` setting.
fn xray_hysteria_inbound(v: &Value, path: &str) -> R<Value> {
    let settings = v
        .get("settings")
        .ok_or_else(|| format!("{path}.settings is required for hysteria"))?;
    hysteria_version_check(settings, path)?;
    let users: Vec<Value> = settings
        .get("users")
        .or_else(|| settings.get("clients"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, user)| {
            user.get("auth")
                .and_then(Value::as_str)
                .filter(|auth| !auth.is_empty())
                .map(|auth| serde_json::json!({ "password": auth }))
                .ok_or_else(|| format!("{path}.settings.users[{index}].auth is required"))
        })
        .collect::<R<_>>()?;
    let mut translated = v.clone();
    translated["protocol"] = Value::from("hysteria2");
    let mut new_settings = settings.clone();
    new_settings["users"] = Value::Array(users);
    if let Some(password) = salamander_password(v) {
        new_settings["obfs"] = serde_json::json!({ "type": "salamander", "password": password });
    }
    // The masquerade lives with the transport's own settings in Xray.
    if let Some(masquerade) = v
        .get("streamSettings")
        .and_then(|stream| stream.get("hysteriaSettings"))
        .and_then(|settings| settings.get("masquerade"))
    {
        new_settings["masquerade"] = masquerade.clone();
    }
    translated["settings"] = new_settings;
    hysteria_transport_to_raw(&mut translated);
    Ok(translated)
}

fn hysteria_version_check(settings: &Value, path: &str) -> R<()> {
    match settings.get("version").and_then(Value::as_u64) {
        None | Some(2) => Ok(()),
        Some(other) => Err(format!(
            "{path}.settings.version: only Hysteria 2 is supported, not {other}"
        )),
    }
}

/// `network: "hysteria"` is plain QUIC to the parser that follows; the
/// transport's own settings have been read.
fn hysteria_transport_to_raw(config: &mut Value) {
    if let Some(stream) = config
        .get_mut("streamSettings")
        .and_then(Value::as_object_mut)
    {
        if stream.get("network").and_then(Value::as_str) == Some("hysteria") {
            stream.insert("network".into(), Value::from("raw"));
        }
        stream.remove("hysteriaSettings");
    }
}

/// The password of a `finalmask.udp` Salamander mask, if there is one.
fn salamander_password(config: &Value) -> Option<String> {
    config
        .get("streamSettings")?
        .get("finalmask")?
        .get("udp")?
        .as_array()?
        .iter()
        .find(|mask| mask.get("type").and_then(Value::as_str) == Some("salamander"))?
        .get("settings")?
        .get("password")?
        .as_str()
        .map(str::to_owned)
}

fn parse_hysteria2(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for hysteria2"))?;
    let server = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first());
    let address = server
        .and_then(|s| s.get("address"))
        .or_else(|| settings.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.address is required for hysteria2"))?;
    let port = server
        .and_then(|s| s.get("port"))
        .or_else(|| settings.get("port"))
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for hysteria2"))?
        as u16;
    let password = server
        .and_then(|s| s.get("password"))
        .or_else(|| settings.get("password"))
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required for hysteria2"))?;
    // sing-box's `"obfs": {"type": "salamander", "password": …}`, or a bare
    // `obfsPassword` next to it.
    let obfs = settings
        .get("obfs")
        .filter(|obfs| !obfs.is_null())
        .or_else(|| {
            server
                .and_then(|s| s.get("obfs"))
                .filter(|obfs| !obfs.is_null())
        });
    let obfs_password = match obfs {
        Some(obfs) => {
            let kind = obfs
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("salamander");
            if !kind.eq_ignore_ascii_case("salamander") {
                return Err(format!(
                    "{path}.settings.obfs.type: only salamander is supported, not {kind:?}"
                ));
            }
            let password = obfs
                .get("password")
                .and_then(Value::as_str)
                .filter(|password| password.len() >= 4)
                .ok_or_else(|| format!("{path}.settings.obfs.password must be at least 4 bytes"))?;
            Some(Box::from(password))
        }
        None => None,
    };
    Ok(OutboundProtocol::Hysteria2(Hysteria2Config {
        address: Address::parse_host(address),
        port,
        password: password.into(),
        obfs_password,
    }))
}

fn parse_tuic(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for tuic"))?;
    let server = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first());
    let address = server
        .and_then(|s| s.get("address"))
        .or_else(|| settings.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.address is required for tuic"))?;
    let port = server
        .and_then(|s| s.get("port"))
        .or_else(|| settings.get("port"))
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for tuic"))? as u16;
    let uuid = server
        .and_then(|s| s.get("uuid"))
        .or_else(|| settings.get("uuid"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.uuid is required for tuic"))
        .and_then(crate::share_link::parse_uuid)
        .map_err(|error| format!("{path}.settings.uuid: {error}"))?;
    let password = server
        .and_then(|s| s.get("password"))
        .or_else(|| settings.get("password"))
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required for tuic"))?;
    Ok(OutboundProtocol::Tuic(TuicConfig {
        address: Address::parse_host(address),
        port,
        uuid,
        password: password.into(),
    }))
}

fn parse_juicity(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for juicity"))?;
    let server = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first());
    let address = server
        .and_then(|s| s.get("address"))
        .or_else(|| settings.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.address is required for juicity"))?;
    let port = server
        .and_then(|s| s.get("port"))
        .or_else(|| settings.get("port"))
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| format!("{path}.settings.port is invalid for juicity"))?
        as u16;
    let uuid = server
        .and_then(|s| s.get("uuid"))
        .or_else(|| settings.get("uuid"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.uuid is required for juicity"))
        .and_then(crate::share_link::parse_uuid)
        .map_err(|error| format!("{path}.settings.uuid: {error}"))?;
    let password = server
        .and_then(|s| s.get("password"))
        .or_else(|| settings.get("password"))
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required for juicity"))?;
    Ok(OutboundProtocol::Juicity(JuicityConfig {
        address: Address::parse_host(address),
        port,
        uuid,
        password: password.into(),
    }))
}

pub(crate) fn parse_amnezia_wireguard(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let settings = settings
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{path}.settings is required for wireguard"))?;
    let peer = settings
        .get("peers")
        .and_then(Value::as_array)
        .and_then(|peers| peers.first())
        .and_then(Value::as_object);
    let private_key = parse_wireguard_key(
        settings
            .get("privateKey")
            .or_else(|| settings.get("secretKey"))
            .and_then(Value::as_str),
        &format!("{path}.settings.privateKey"),
    )?;
    let peer_public_key = parse_wireguard_key(
        settings
            .get("peerPublicKey")
            .or_else(|| settings.get("publicKey"))
            .or_else(|| peer.and_then(|peer| peer.get("publicKey")))
            .and_then(Value::as_str),
        &format!("{path}.settings.peerPublicKey"),
    )?;
    let preshared_key = parse_optional_wireguard_key(
        settings
            .get("presharedKey")
            .or_else(|| settings.get("preSharedKey"))
            .or_else(|| peer.and_then(|peer| peer.get("presharedKey")))
            .or_else(|| peer.and_then(|peer| peer.get("preSharedKey"))),
        &format!("{path}.settings.presharedKey"),
    )?;

    let endpoint = settings
        .get("endpoint")
        .and_then(Value::as_str)
        .or_else(|| {
            peer.and_then(|peer| peer.get("endpoint"))
                .and_then(Value::as_str)
        });
    let (address, port) = if let Some(endpoint) = endpoint {
        parse_wireguard_endpoint(endpoint, path)?
    } else {
        let address = settings
            .get("server")
            .and_then(|server| server.get("address"))
            .or_else(|| settings.get("remoteAddress"))
            .or_else(|| settings.get("proxyAddress"))
            .or_else(|| settings.get("address"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{path}.settings.endpoint or address is required"))?;
        let port = settings
            .get("server")
            .and_then(|server| server.get("port"))
            .or_else(|| peer.and_then(|peer| peer.get("port")))
            .or_else(|| settings.get("port"))
            .and_then(Value::as_u64)
            .filter(|port| *port > 0 && *port <= u16::MAX as u64)
            .ok_or_else(|| format!("{path}.settings.port is invalid for wireguard"))?
            as u16;
        (Address::parse_host(address), port)
    };
    let tunnel_address_value = settings
        .get("tunnelAddress")
        .or_else(|| settings.get("localAddress"))
        .or_else(|| settings.get("ip"))
        .or_else(|| settings.get("address"));
    let tunnel_address = match tunnel_address_value {
        Some(Value::String(value)) => parse_wireguard_tunnel_address(value, path)?,
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find_map(|value| parse_wireguard_tunnel_address(value, path).ok())
            .ok_or_else(|| format!("{path}.settings.address has no IP address"))?,
        Some(_) => {
            return Err(format!(
                "{path}.settings.tunnelAddress or address must be a string or array"
            ))
        }
        None => {
            return Err(format!(
                "{path}.settings.tunnelAddress or address is required"
            ))
        }
    };

    let amnezia = settings
        .get("amnezia-wg-option")
        .or_else(|| settings.get("amnezia"))
        .or_else(|| settings.get("amneziaSettings"));
    let junk_count = parse_amnezia_u16(amnezia, &["jc", "Jc"], 0, path)?;
    let junk_min = parse_amnezia_u16(amnezia, &["jmin", "Jmin"], 0, path)?;
    let junk_max = parse_amnezia_u16(amnezia, &["jmax", "Jmax"], junk_min, path)?;
    let s1 = parse_amnezia_u16(amnezia, &["s1", "S1"], 0, path)?;
    let s2 = parse_amnezia_u16(amnezia, &["s2", "S2"], 0, path)?;
    let s3 = parse_amnezia_u16(amnezia, &["s3", "S3"], 0, path)?;
    let s4 = parse_amnezia_u16(amnezia, &["s4", "S4"], 0, path)?;
    let h1 = parse_amnezia_header(amnezia, &["h1", "H1"], 1, path)?;
    let h2 = parse_amnezia_header(amnezia, &["h2", "H2"], 2, path)?;
    let h3 = parse_amnezia_header(amnezia, &["h3", "H3"], 3, path)?;
    let h4 = parse_amnezia_header(amnezia, &["h4", "H4"], 4, path)?;
    let persistent_keepalive = settings
        .get("persistentKeepalive")
        .or_else(|| settings.get("keepAlive"))
        .or_else(|| peer.and_then(|peer| peer.get("keepAlive")))
        .and_then(Value::as_u64)
        .map(|value| value.min(u16::MAX as u64) as u16);

    let reserved = parse_wireguard_reserved(
        settings
            .get("reserved")
            .or_else(|| peer.and_then(|peer| peer.get("reserved"))),
        path,
    )?;

    Ok(OutboundProtocol::AmneziaWireguard(AmneziaWireguardConfig {
        has_wireguard: true,
        route: WarpRoute::WireGuard,
        masque: None,
        exits: Vec::new(),
        hybrid: HybridMode::WarpFirst,
        prefer_exit: false,
        inner: None,
        reserved,
        address,
        port,
        private_key,
        peer_public_key,
        preshared_key,
        tunnel_address,
        persistent_keepalive,
        junk_count,
        junk_min,
        junk_max,
        s1,
        s2,
        s3,
        s4,
        h1,
        h2,
        h3,
        h4,
    }))
}

/// A Cloudflare WARP outbound that can reach the account over WireGuard,
/// MASQUE over HTTP/2 or MASQUE over HTTP/3.
///
/// ```json
/// {"protocol": "warp", "settings": {
///   "route": "auto",
///   "wireguard": { ...an ordinary wireguard/amnezia-wg settings object... },
///   "masque": {
///     "privateKey": "<base64 DER, or PEM>",
///     "serverPublicKey": "<PEM or base64 SubjectPublicKeyInfo>",
///     "address": ["172.16.0.2", "2606:4700:110:8a36::1"],
///     "http2Endpoints": ["162.159.198.4"], "http3Endpoints": ["162.159.198.1"],
///     "http2Sni": "www.speedtest.net"
///   },
///   "inner": { ...a wireguard settings object of a second account... }
/// }}
/// ```
///
/// Either half may be left out; `route` defaults to `auto`. `inner` is WARP
/// inside WARP: that account's WireGuard runs inside the MASQUE tunnel, so the
/// exit is located where Cloudflare's edge is rather than where the user is.
pub(crate) fn parse_warp(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let object = settings
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{path}.settings is required for warp"))?;
    let route = match object.get("route") {
        None | Some(Value::Null) => WarpRoute::Auto,
        Some(value) => value.as_str().and_then(WarpRoute::parse).ok_or_else(|| {
            format!("{path}.settings.route must be auto, wireguard, masque-h2 or masque-h3")
        })?,
    };
    let masque = object
        .get("masque")
        .filter(|value| !value.is_null())
        .map(|value| parse_masque(value, path).map(Box::new))
        .transpose()?;
    let mut config = match object.get("wireguard").filter(|value| !value.is_null()) {
        Some(wireguard) => {
            let mut wireguard = wireguard.clone();
            // An account has one tunnel address; the WireGuard half may leave
            // it to the MASQUE half.
            if let (Some(map), Some(masque)) = (wireguard.as_object_mut(), &masque) {
                let has_address = ["tunnelAddress", "localAddress", "ip", "address"]
                    .iter()
                    .any(|key| map.contains_key(*key));
                let first = masque
                    .addresses
                    .iter()
                    .find(|address| address.is_ipv4())
                    .or(masque.addresses.first());
                if let (false, Some(address)) = (has_address, first) {
                    map.insert("address".into(), address.to_string().into());
                }
            }
            match parse_amnezia_wireguard(Some(&wireguard), path)? {
                OutboundProtocol::AmneziaWireguard(config) => config,
                _ => unreachable!("parse_amnezia_wireguard returns WireGuard"),
            }
        }
        None => {
            let masque = masque
                .as_ref()
                .ok_or_else(|| format!("{path}.settings needs a wireguard or a masque block"))?;
            let endpoint = masque
                .http2_endpoints
                .first()
                .or(masque.http3_endpoints.first())
                .ok_or_else(|| format!("{path}.settings.masque has no endpoint"))?;
            let header = |value: u32| AmneziaHeaderRange {
                min: value,
                max: value,
            };
            AmneziaWireguardConfig {
                address: Address::Ip(endpoint.ip()),
                port: endpoint.port(),
                private_key: [0; 32],
                peer_public_key: [0; 32],
                preshared_key: None,
                tunnel_address: masque
                    .addresses
                    .first()
                    .copied()
                    .ok_or_else(|| format!("{path}.settings.masque.address is required"))?,
                persistent_keepalive: None,
                junk_count: 0,
                junk_min: 0,
                junk_max: 0,
                s1: 0,
                s2: 0,
                s3: 0,
                s4: 0,
                h1: header(1),
                h2: header(2),
                h3: header(3),
                h4: header(4),
                reserved: [0; 3],
                has_wireguard: false,
                route,
                masque: None,
                exits: Vec::new(),
                hybrid: HybridMode::WarpFirst,
                prefer_exit: false,
                inner: None,
            }
        }
    };
    config.route = route;
    config.inner = match object.get("inner").filter(|value| !value.is_null()) {
        Some(inner) => {
            match parse_amnezia_wireguard(Some(inner), &format!("{path}.settings.inner"))? {
                OutboundProtocol::AmneziaWireguard(inner) if masque.is_some() => {
                    Some(Box::new(inner))
                }
                OutboundProtocol::AmneziaWireguard(_) => {
                    return Err(format!(
                "{path}.settings.inner rides inside the MASQUE tunnel, so it needs a masque block"
            ))
                }
                _ => unreachable!("parse_amnezia_wireguard returns WireGuard"),
            }
        }
        None => None,
    };
    config.masque = masque;
    (config.exits, config.hybrid, config.prefer_exit) = parse_exits(object, path)?;
    Ok(OutboundProtocol::AmneziaWireguard(config))
}

/// The `exits` of a `warp` outbound and the order they go in.
///
/// ```json
/// {"mode": "server-first", "exits": ["vless://…", "trojan://…"]}
/// ```
///
/// `server-first` (the UI's "hybrid") dials a listed server and reaches
/// Cloudflare's tunnel through it; `warp-first` (the UI's "reverse hybrid")
/// brings the tunnel up directly and dials a listed server from inside it,
/// with `preferExit` deciding whether the server or the tunnel alone carries
/// traffic first. A missing `mode` is `warp-first`.
///
/// Builds before these names wrote `hybrid` for the tunnel first and
/// `reverse` for a server first inside the tunnel; both keep that meaning, so
/// an account saved by an older build keeps its path.
fn parse_exits(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> R<(Vec<Arc<str>>, HybridMode, bool)> {
    let (hybrid, legacy_prefer) = match object.get("mode").and_then(Value::as_str) {
        None | Some("warp-first") | Some("hybrid") => (HybridMode::WarpFirst, false),
        Some("reverse") => (HybridMode::WarpFirst, true),
        Some("server-first") => (HybridMode::ServerFirst, false),
        Some(other) => {
            return Err(format!(
                "{path}.settings.mode must be server-first or warp-first, not {other:?}"
            ))
        }
    };
    let prefer_exit = hybrid == HybridMode::WarpFirst
        && (legacy_prefer || object.get("preferExit").and_then(Value::as_bool) == Some(true));
    let mut exits = Vec::new();
    for (index, link) in object
        .get("exits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let link = link
            .as_str()
            .ok_or_else(|| format!("{path}.settings.exits[{index}] must be a share link"))?;
        let parsed = crate::share_link::parse_link(link)
            .map_err(|error| format!("{path}.settings.exits[{index}]: {error}"))?;
        if !parsed.outbound.chainable() {
            return Err(format!(
                "{path}.settings.exits[{index}]: {} over this transport cannot follow a tunnel",
                parsed.outbound.protocol.name()
            ));
        }
        exits.push(Arc::from(link));
    }
    if prefer_exit && exits.is_empty() {
        return Err(format!(
            "{path}.settings.preferExit needs at least one exit"
        ));
    }
    Ok((exits, hybrid, prefer_exit))
}

/// Base64 of a key that may come as a PEM block or with URL-safe letters.
fn decode_key_material(text: &str, what: &str, path: &str) -> R<Vec<u8>> {
    use base64::Engine;
    let body: String = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    engines
        .iter()
        .find_map(|engine| engine.decode(body.as_bytes()).ok())
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| format!("{path}.settings.masque.{what} is not valid base64 or PEM"))
}

fn parse_masque(value: &Value, path: &str) -> R<MasqueConfig> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path}.settings.masque must be an object"))?;
    let text = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| object.get(*key))
            .and_then(Value::as_str)
    };
    let private_key = decode_key_material(
        text(&["privateKey", "secretKey"])
            .ok_or_else(|| format!("{path}.settings.masque.privateKey is required"))?,
        "privateKey",
        path,
    )?;
    let server_public_key = decode_key_material(
        text(&["serverPublicKey", "endpointPublicKey", "peerPublicKey"])
            .ok_or_else(|| format!("{path}.settings.masque.serverPublicKey is required"))?,
        "serverPublicKey",
        path,
    )?;
    let addresses: Vec<std::net::IpAddr> =
        match object.get("address").or(object.get("addresses")) {
            Some(Value::String(text)) => vec![text.as_str()],
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        }
        .into_iter()
        .flat_map(|text| text.split([',', ' ']))
        .filter_map(|address| address.trim().split('/').next()?.parse().ok())
        .collect();
    if addresses.is_empty() {
        return Err(format!("{path}.settings.masque.address is required"));
    }
    let port = match object.get("port") {
        None | Some(Value::Null) => 443,
        Some(value) => value
            .as_u64()
            .filter(|port| *port > 0 && *port <= u64::from(u16::MAX))
            .ok_or_else(|| format!("{path}.settings.masque.port is invalid"))?
            as u16,
    };
    let endpoints = |keys: &[&str], defaults: &[&str]| -> R<Vec<std::net::SocketAddr>> {
        let Some(items) = keys.iter().find_map(|key| object.get(*key)) else {
            return Ok(MasqueConfig::default_endpoints(defaults));
        };
        let items: Vec<&str> = match items {
            Value::String(text) => vec![text.as_str()],
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => return Err(format!("{path}.settings.masque.{} is invalid", keys[0])),
        };
        items
            .into_iter()
            .map(|text| {
                text.parse::<std::net::SocketAddr>()
                    .or_else(|_| {
                        text.trim_matches(['[', ']'])
                            .parse::<std::net::IpAddr>()
                            .map(|ip| std::net::SocketAddr::new(ip, port))
                    })
                    .map_err(|_| {
                        format!(
                            "{path}.settings.masque.{}: {text:?} is not an IP address",
                            keys[0]
                        )
                    })
            })
            .collect()
    };
    Ok(MasqueConfig {
        private_key,
        server_public_key,
        addresses,
        http2_endpoints: endpoints(
            &["http2Endpoints", "h2Endpoints"],
            &MasqueConfig::DEFAULT_HTTP2_ENDPOINTS,
        )?,
        http3_endpoints: endpoints(
            &["http3Endpoints", "h3Endpoints"],
            &MasqueConfig::DEFAULT_HTTP3_ENDPOINTS,
        )?,
        http2_sni: Arc::from(
            text(&["http2Sni", "h2Sni"]).unwrap_or(MasqueConfig::DEFAULT_HTTP2_SNI),
        ),
        http3_sni: Arc::from(
            text(&["http3Sni", "h3Sni"]).unwrap_or(MasqueConfig::DEFAULT_HTTP3_SNI),
        ),
        authority: Arc::from(text(&["authority"]).unwrap_or(MasqueConfig::DEFAULT_AUTHORITY)),
    })
}

/// Xray's `reserved`: three numbers, or WARP's `client_id` in base64.
fn parse_wireguard_reserved(value: Option<&Value>, path: &str) -> R<[u8; 3]> {
    match value {
        None | Some(Value::Null) => Ok([0; 3]),
        Some(Value::Array(items)) => {
            let bytes: Vec<u8> = items
                .iter()
                .map(|item| item.as_u64().filter(|v| *v <= 255).map(|v| v as u8))
                .collect::<Option<_>>()
                .ok_or_else(|| format!("{path}.settings.reserved must be three bytes"))?;
            <[u8; 3]>::try_from(bytes)
                .map_err(|_| format!("{path}.settings.reserved must be three bytes"))
        }
        Some(Value::String(text)) => {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| format!("{path}.settings.reserved is not base64"))?;
            <[u8; 3]>::try_from(bytes)
                .map_err(|_| format!("{path}.settings.reserved must be three bytes"))
        }
        Some(_) => Err(format!(
            "{path}.settings.reserved must be an array or base64 text"
        )),
    }
}

fn parse_wireguard_key(value: Option<&str>, path: &str) -> R<[u8; 32]> {
    let value = value.ok_or_else(|| format!("{path} is required"))?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
        .map_err(|error| format!("{path} is not valid base64: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{path} must decode to exactly 32 bytes"))
}

fn parse_optional_wireguard_key(value: Option<&Value>, path: &str) -> R<Option<[u8; 32]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("{path} must be a base64 string"))?;
    // Panels write `"preSharedKey": ""` for "none".
    if value.trim().is_empty() {
        return Ok(None);
    }
    parse_wireguard_key(Some(value), path).map(Some)
}

/// Xray's `wireguard` inbound: `secretKey`, `peers` (`publicKey`,
/// `preSharedKey`, `allowedIPs`, `keepAlive`, `email`) and `mtu`.
fn parse_wireguard_inbound(settings: Option<&Value>, path: &str) -> R<WireGuardInboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for wireguard"))?;
    let secret_key = parse_wireguard_key(
        settings.get("secretKey").and_then(Value::as_str),
        &format!("{path}.settings.secretKey"),
    )?;
    let mtu = match settings.get("mtu").and_then(Value::as_u64) {
        None | Some(0) => 1420,
        Some(mtu @ 576..=9000) => mtu as usize,
        Some(other) => return Err(format!("{path}.settings.mtu {other} is outside 576..=9000")),
    };
    let mut peers = Vec::new();
    for (index, peer) in settings
        .get("peers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let peer_path = format!("{path}.settings.peers[{index}]");
        let allowed_ips = match peer.get("allowedIPs").and_then(Value::as_array) {
            // Xray's default: the peer may use any address.
            None => ["0.0.0.0/0", "::/0"]
                .iter()
                .filter_map(|text| routing::ipnet_lite::Cidr::parse(text))
                .collect(),
            Some(list) => list
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .and_then(routing::ipnet_lite::Cidr::parse)
                        .ok_or_else(|| {
                            format!("{peer_path}.allowedIPs has {entry} which is not a CIDR")
                        })
                })
                .collect::<R<Vec<_>>>()?,
        };
        peers.push(WireGuardPeer {
            public_key: parse_wireguard_key(
                peer.get("publicKey").and_then(Value::as_str),
                &format!("{peer_path}.publicKey"),
            )?,
            preshared_key: parse_optional_wireguard_key(
                peer.get("preSharedKey")
                    .or_else(|| peer.get("presharedKey")),
                &format!("{peer_path}.preSharedKey"),
            )?,
            allowed_ips: allowed_ips.into_boxed_slice(),
            keepalive: peer
                .get("keepAlive")
                .and_then(Value::as_u64)
                .filter(|seconds| *seconds > 0)
                .and_then(|seconds| u16::try_from(seconds).ok()),
            email: peer
                .get("email")
                .and_then(Value::as_str)
                .filter(|email| !email.is_empty())
                .map(Arc::from),
        });
    }
    if peers.is_empty() {
        return Err(format!("{path}.settings.peers needs at least one peer"));
    }
    Ok(WireGuardInboundConfig {
        secret_key,
        mtu,
        peers: peers.into_boxed_slice(),
    })
}

/// The `dns` outbound's `rules`, or the legacy `blockTypes` and `nonIPQuery`
/// that Xray turns into rules. `direct` (forward the query to its real
/// server) is refused: this outbound answers DNS itself and has nothing to
/// forward with, and a rule that quietly did something else would be worse.
fn parse_dns_outbound_rules(settings: Option<&Value>, path: &str) -> R<Box<[DnsOutboundRule]>> {
    let Some(settings) = settings else {
        return Ok(Box::new([]));
    };
    let legacy = settings.get("blockTypes").is_some() || settings.get("nonIPQuery").is_some();
    if legacy && settings.get("rules").is_some() {
        return Err(format!(
            "{path}.settings: nonIPQuery and blockTypes cannot be mixed with rules"
        ));
    }
    if legacy {
        let mode = settings
            .get("nonIPQuery")
            .and_then(Value::as_str)
            .filter(|mode| !mode.is_empty())
            .unwrap_or("reject");
        let action = match mode {
            "reject" => DnsAction::Return(5),
            "drop" | "skip" => DnsAction::Drop,
            other => return Err(format!("{path}.settings.nonIPQuery {other:?} is unknown")),
        };
        let qtypes: Vec<u16> = settings
            .get("blockTypes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_u64().and_then(|n| u16::try_from(n).ok()))
            .collect();
        return Ok(if qtypes.is_empty() {
            Box::new([])
        } else {
            Box::new([DnsOutboundRule {
                action,
                qtypes: qtypes.into_boxed_slice(),
                domains: Box::new([]),
            }])
        });
    }
    let mut rules = Vec::new();
    for (index, rule) in settings
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let rule_path = format!("{path}.settings.rules[{index}]");
        let action = match rule
            .get("action")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("hijack") => DnsAction::Hijack,
            Some("drop") => DnsAction::Drop,
            Some("return") => {
                let code = rule.get("rCode").and_then(Value::as_u64).unwrap_or(0);
                DnsAction::Return(
                    u8::try_from(code)
                        .ok()
                        .filter(|code| *code <= 15)
                        .ok_or_else(|| format!("{rule_path}.rCode {code} is not 0-15"))?,
                )
            }
            Some("direct") => {
                return Err(format!(
                    "{rule_path}.action \"direct\" is not supported: the dns outbound answers queries itself"
                ))
            }
            other => return Err(format!("{rule_path}.action {other:?} is unknown")),
        };
        // `qType` is a port-style list: 28, "1,28", "64-66".
        let mut qtypes = Vec::new();
        match rule.get("qType") {
            None | Some(Value::Null) => {}
            Some(Value::Number(number)) => {
                qtypes.extend(number.as_u64().and_then(|n| u16::try_from(n).ok()))
            }
            Some(Value::String(text)) => {
                for part in text
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                {
                    let (from, to) = part.split_once('-').unwrap_or((part, part));
                    let (Ok(from), Ok(to)) = (from.trim().parse::<u16>(), to.trim().parse::<u16>())
                    else {
                        return Err(format!("{rule_path}.qType {part:?} is not a type or range"));
                    };
                    qtypes.extend(from..=to.max(from));
                }
            }
            Some(_) => return Err(format!("{rule_path}.qType must be a number or string")),
        }
        let domains: Vec<routing::DomainPattern> = rule
            .get("domain")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(routing::DomainPattern::parse)
            .collect();
        if domains.iter().any(|pattern| {
            matches!(
                pattern,
                routing::DomainPattern::Regex(_) | routing::DomainPattern::Geosite(_)
            )
        }) {
            return Err(format!(
                "{rule_path}.domain takes full:, domain: and keyword: names here, not regexp: or geosite:"
            ));
        }
        rules.push(DnsOutboundRule {
            action,
            qtypes: qtypes.into_boxed_slice(),
            domains: domains.into_boxed_slice(),
        });
    }
    Ok(rules.into_boxed_slice())
}

/// Blackhole's `response`: `{"type": "none" | "http" | "custom",
/// "customResponseData": <base64>}`.
fn parse_blackhole_response(settings: Option<&Value>, path: &str) -> R<Option<Arc<[u8]>>> {
    let Some(response) = settings
        .and_then(|s| s.get("response"))
        .filter(|r| r.is_object())
    else {
        return Ok(None);
    };
    match response
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("") | Some("none") => Ok(None),
        Some("http") => Ok(Some(Arc::from(
            &b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n\r\n\r\n"[..],
        ))),
        Some("custom") => {
            use base64::Engine;
            let data = response
                .get("customResponseData")
                .and_then(Value::as_str)
                .unwrap_or("");
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .map(|bytes| Some(Arc::from(bytes)))
                .map_err(|error| {
                    format!("{path}.settings.response.customResponseData is not base64: {error}")
                })
        }
        Some(other) => Err(format!("{path}.settings.response.type {other:?} is unknown")),
    }
}

fn parse_wireguard_endpoint(value: &str, path: &str) -> R<(Address, u16)> {
    if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
        return Ok((Address::Ip(socket.ip()), socket.port()));
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| format!("{path}.settings.endpoint is invalid"))?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .ok_or_else(|| format!("{path}.settings.endpoint must include a port"))?
    };
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("{path}.settings.endpoint port is invalid"))?;
    Ok((Address::parse_host(host), port))
}

fn parse_wireguard_tunnel_address(value: &str, path: &str) -> R<std::net::IpAddr> {
    value
        .split([',', ' '])
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .find_map(|address| {
            address
                .split('/')
                .next()
                .and_then(|address| address.parse::<std::net::IpAddr>().ok())
        })
        .ok_or_else(|| format!("{path}.settings.tunnelAddress must include an IP address"))
}

fn parse_amnezia_u16(value: Option<&Value>, keys: &[&str], default: u16, path: &str) -> R<u16> {
    let Some(value) = keys
        .iter()
        .find_map(|key| value.and_then(|object| object.get(*key)))
    else {
        return Ok(default);
    };
    value
        .as_u64()
        .filter(|value| *value <= u16::MAX as u64)
        .map(|value| value as u16)
        .ok_or_else(|| format!("{path}.settings.{}.value is invalid", keys[0]))
}

fn parse_amnezia_header(
    value: Option<&Value>,
    keys: &[&str],
    default: u32,
    path: &str,
) -> R<AmneziaHeaderRange> {
    let Some(value) = keys
        .iter()
        .find_map(|key| value.and_then(|object| object.get(*key)))
    else {
        return Ok(AmneziaHeaderRange {
            min: default,
            max: default,
        });
    };
    let (min, max) = match value {
        Value::Number(value) => {
            let number = value
                .as_u64()
                .filter(|number| *number <= u32::MAX as u64)
                .ok_or_else(|| format!("{path}.settings.{} is invalid", keys[0]))?
                as u32;
            (number, number)
        }
        Value::String(value) => {
            let value = value.trim();
            if let Some((min, max)) = value.split_once('-') {
                (
                    min.trim()
                        .parse::<u32>()
                        .map_err(|_| format!("{path}.settings.{} is invalid", keys[0]))?,
                    max.trim()
                        .parse::<u32>()
                        .map_err(|_| format!("{path}.settings.{} is invalid", keys[0]))?,
                )
            } else {
                let number = value
                    .parse::<u32>()
                    .map_err(|_| format!("{path}.settings.{} is invalid", keys[0]))?;
                (number, number)
            }
        }
        _ => return Err(format!("{path}.settings.{} is invalid", keys[0])),
    };
    if min > max {
        return Err(format!("{path}.settings.{} range is inverted", keys[0]));
    }
    Ok(AmneziaHeaderRange { min, max })
}

fn parse_hysteria2_inbound(settings: Option<&Value>, path: &str) -> R<Hysteria2InboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for hysteria2"))?;
    let mut passwords = Vec::new();
    if let Some(password) = settings.get("password").and_then(Value::as_str) {
        if password.is_empty() {
            return Err(format!("{path}.settings.password must not be empty"));
        }
        passwords.push(password.into());
    }
    if let Some(users) = settings.get("users").and_then(Value::as_array) {
        for (index, user) in users.iter().enumerate() {
            let password = user
                .get("password")
                .and_then(Value::as_str)
                .filter(|password| !password.is_empty())
                .ok_or_else(|| format!("{path}.settings.users[{index}].password is required"))?;
            passwords.push(password.into());
        }
    }
    if passwords.is_empty() {
        return Err(format!(
            "{path}.settings.password or settings.users is required for hysteria2"
        ));
    }
    let obfs_password = match settings.get("obfs").filter(|obfs| !obfs.is_null()) {
        Some(obfs) => {
            let kind = obfs
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("salamander");
            if !kind.eq_ignore_ascii_case("salamander") {
                return Err(format!(
                    "{path}.settings.obfs.type: only salamander is supported, not {kind:?}"
                ));
            }
            let password = obfs
                .get("password")
                .and_then(Value::as_str)
                .filter(|password| password.len() >= 4)
                .ok_or_else(|| format!("{path}.settings.obfs.password must be at least 4 bytes"))?;
            Some(Box::from(password))
        }
        None => None,
    };
    Ok(Hysteria2InboundConfig {
        passwords: passwords.into_boxed_slice(),
        obfs_password,
        masquerade: parse_hysteria_masquerade(settings.get("masquerade"), path)?,
    })
}

/// Hysteria's `masquerade`: `{"type": "string" | "file" | "proxy", ...}`.
/// `insecure`, `rewriteHost` and `xForwarded` of a proxy are not applied: the
/// page is fetched like any other, with certificate checks and the site's own
/// name in `Host`.
fn parse_hysteria_masquerade(value: Option<&Value>, path: &str) -> R<Option<Hysteria2Masquerade>> {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return Ok(None);
    };
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    };
    let kind = text("type").unwrap_or("").to_ascii_lowercase();
    Ok(Some(match kind.as_str() {
        "" => return Ok(None),
        "string" => {
            let status = value
                .get("statusCode")
                .and_then(Value::as_u64)
                .map_or(200, |code| code.clamp(100, 599) as u16);
            let headers = value
                .get("headers")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter_map(|(name, content)| {
                    Some((name.as_str().into(), content.as_str()?.into()))
                })
                .collect();
            Hysteria2Masquerade::Text {
                status,
                headers,
                content: text("content").unwrap_or("").into(),
            }
        }
        "file" => Hysteria2Masquerade::Files {
            dir: text("dir")
                .ok_or_else(|| format!("{path}.settings.masquerade.dir is required for file"))?
                .into(),
        },
        "proxy" => {
            let url = text("url")
                .ok_or_else(|| format!("{path}.settings.masquerade.url is required for proxy"))?;
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!(
                    "{path}.settings.masquerade.url must be an http or https URL"
                ));
            }
            Hysteria2Masquerade::Proxy { url: url.into() }
        }
        other => {
            return Err(format!(
                "{path}.settings.masquerade.type {other:?} is not string, file or proxy"
            ))
        }
    }))
}

fn parse_tuic_inbound(settings: Option<&Value>, path: &str) -> R<TuicInboundConfig> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for tuic"))?;
    let uuid = settings
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.settings.uuid is required for tuic"))
        .and_then(crate::share_link::parse_uuid)
        .map_err(|error| format!("{path}.settings.uuid: {error}"))?;
    let password = settings
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{path}.settings.password is required for tuic"))?;
    Ok(TuicInboundConfig {
        uuid,
        password: password.into(),
    })
}

fn parse_tun_inbound(settings: Option<&Value>, path: &str) -> R<TunInboundConfig> {
    let settings = settings.and_then(Value::as_object);
    let mut config = TunInboundConfig::default();
    if let Some(name) = settings.and_then(|value| {
        value
            .get("name")
            .or_else(|| value.get("device"))
            .or_else(|| value.get("deviceName"))
            .and_then(Value::as_str)
    }) {
        if name.is_empty() || name.len() >= 16 {
            return Err(format!("{path}.settings.name is not a valid TUN name"));
        }
        config.name = name.into();
    }
    if let Some(mtu) = settings.and_then(|value| {
        value
            .get("mtu")
            .or_else(|| value.get("MTU"))
            .and_then(Value::as_u64)
    }) {
        config.mtu = usize::try_from(mtu)
            .ok()
            .filter(|value| (576..=65_535).contains(value))
            .ok_or_else(|| format!("{path}.settings.mtu must be between 576 and 65535"))?;
    }
    if let Some(value) = settings.and_then(|value| value.get("tcp").and_then(Value::as_bool)) {
        config.enable_tcp = value;
    }
    if let Some(value) = settings.and_then(|value| value.get("udp").and_then(Value::as_bool)) {
        config.enable_udp = value;
    }
    if let Some(value) = settings.and_then(|value| value.get("icmp").and_then(Value::as_bool)) {
        config.enable_icmp = value;
    }
    if let Some(settings) = settings {
        let mut address_values = Vec::new();
        for key in ["addresses", "address", "inet4Address", "inet6Address"] {
            if let Some(value) = settings.get(key) {
                address_values.push((key, value));
            }
        }
        if !address_values.is_empty() {
            let mut addresses = Vec::new();
            for (key, value) in address_values {
                addresses.extend(parse_tun_cidr_list(
                    value,
                    &format!("{path}.settings.{key}"),
                )?);
            }
            addresses.sort();
            addresses.dedup();
            config.addresses = addresses.into_boxed_slice();
        }
    }
    if let Some(value) = settings.and_then(|value| value.get("routes")) {
        config.routes = parse_tun_cidr_list(value, &format!("{path}.settings.routes"))?;
    }
    if let Some(value) = settings.and_then(|value| {
        value
            .get("autoRoute")
            .or_else(|| value.get("auto_route"))
            .and_then(Value::as_bool)
    }) {
        config.auto_route = value;
    }
    if let Some(value) = settings.and_then(|value| {
        value
            .get("strictRoute")
            .or_else(|| value.get("strict_route"))
            .and_then(Value::as_bool)
    }) {
        config.strict_route = value;
    }
    if !config.enable_tcp && config.enable_icmp {
        return Err(format!("{path}.settings.icmp requires TCP support"));
    }
    if config.strict_route && !config.auto_route {
        return Err(format!("{path}.settings.strictRoute requires autoRoute"));
    }
    if config.auto_route && config.routes.is_empty() {
        return Err(format!(
            "{path}.settings.autoRoute requires an explicit routes list"
        ));
    }
    Ok(config)
}

fn parse_tun_cidr_list(value: &Value, path: &str) -> R<Box<[Box<str>]>> {
    let values: Vec<&str> = match value {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| format!("{path} must contain only CIDR strings"))
            })
            .collect::<R<Vec<_>>>()?,
        _ => return Err(format!("{path} must be a CIDR string or array")),
    };
    if values.is_empty() {
        return Err(format!("{path} must not be empty"));
    }
    values
        .into_iter()
        .map(|value| {
            let (address, prefix) = value
                .trim()
                .split_once('/')
                .ok_or_else(|| format!("{path} contains {value:?} without a prefix"))?;
            let address = address
                .parse::<std::net::IpAddr>()
                .map_err(|_| format!("{path} contains invalid address {address:?}"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| format!("{path} contains invalid prefix {prefix:?}"))?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("{path} contains an out-of-range prefix"));
            }
            Ok(value.trim().into())
        })
        .collect::<R<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

// --------------------------------------------------------------- stream

fn parse_stream(v: &Value, path: &str, out: &mut ParseOutput) -> R<StreamSettings> {
    let network = v.get("network").and_then(Value::as_str).unwrap_or("raw");

    let mut transport = match network {
        "raw" | "tcp" => Transport::Raw,
        "ws" => Transport::WebSocket(parse_ws(v.get("wsSettings"))),
        "httpupgrade" => Transport::HttpUpgrade(parse_ws(v.get("httpupgradeSettings"))),
        "grpc" => Transport::Grpc(parse_grpc(v.get("grpcSettings"))),
        "xhttp" | "splithttp" => Transport::Xhttp(parse_xhttp(xhttp_settings(v), v, path)?),
        other => {
            return Err(format!(
                "{path}.streamSettings.network: unsupported transport {other:?}"
            ))
        }
    };

    // Transport and socket settings Zray accepts and has no use for: it keeps
    // connections alive on its own (see `zero_evasion::KeepaliveCarrier`),
    // resolves names its own way, and does not read `X-Forwarded-For`.
    for (section, keys) in [
        (
            "wsSettings",
            &["heartbeatPeriod", "trustedXForwardedFor"][..],
        ),
        ("httpupgradeSettings", &["trustedXForwardedFor"][..]),
        (
            "sockopt",
            &["addressPortStrategy", "penetrate", "trustedXForwardedFor"][..],
        ),
    ] {
        for key in keys {
            if v.get(section)
                .and_then(|settings| settings.get(*key))
                .is_some_and(|value| {
                    !value.is_null() && value != "" && value != false && value != 0
                })
            {
                out.note(
                    format!("{path}.streamSettings.{section}.{key}"),
                    "accepted, not applied: Zray has no such setting",
                );
            }
        }
    }

    // Panels write `"security": ""` for "none" as well as omitting it.
    let security = match v.get("security").and_then(Value::as_str).unwrap_or("none") {
        "none" | "" => Security::None,
        "tls" => {
            let t = v.get("tlsSettings");
            // What Zray's TLS takes from the browser fingerprint, or from the
            // bundled roots, and so does not let a setting override.
            for key in [
                "minVersion",
                "maxVersion",
                "cipherSuites",
                "curvePreferences",
                "disableSystemRoot",
                "enableSessionResumption",
                "echForceQuery",
                "echSockopt",
                "ocspStapling",
                "useSystemCA",
                "buildChain",
                "oneTimeLoading",
            ] {
                if t.is_some_and(|t| {
                    t.get(key)
                        .is_some_and(|value| !value.is_null() && value != "" && value != false)
                }) {
                    out.note(
                        format!("{path}.streamSettings.tlsSettings.{key}"),
                        "accepted, not applied: the TLS shape comes from `fingerprint`",
                    );
                }
            }
            let allow_insecure = t
                .and_then(|t| t.get("allowInsecure"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ech = parse_ech_config(t, path)?;
            let trusted_roots = parse_trusted_roots(t, path)?;
            let pinned_cert_sha256 = match t.and_then(|t| t.get("pinnedPeerCertSha256")) {
                Some(Value::String(text)) => parse_cert_pins(text),
                Some(Value::Array(items)) => parse_cert_pins(
                    &items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                _ => Ok(Vec::new()),
            }
            .map_err(|error| {
                format!("{path}.streamSettings.tlsSettings.pinnedPeerCertSha256: {error}")
            })?;
            Security::Tls(TlsConfig {
                trusted_roots,
                pinned_cert_sha256,
                verify_names: match t.and_then(|t| t.get("verifyPeerCertByName")) {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::String(text)) => text
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(Box::from)
                        .collect(),
                    Some(Value::Array(names)) => names
                        .iter()
                        .filter_map(Value::as_str)
                        .map(Box::from)
                        .collect(),
                    Some(_) => {
                        return Err(format!(
                            "{path}.streamSettings.tlsSettings.verifyPeerCertByName must be a name or a list of names"
                        ))
                    }
                },
                key_log_file: t
                    .and_then(|t| t.get("masterKeyLog"))
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(Box::from),
                server_name: t
                    .and_then(|t| t.get("serverName"))
                    .and_then(Value::as_str)
                    .map(Arc::from),
                alpn: t
                    .and_then(|t| t.get("alpn"))
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(Box::from).collect())
                    .unwrap_or_default(),
                fingerprint: parse_fingerprint(t, path)?,
                allow_insecure,
                ech,
            })
        }
        "reality" => {
            let r = v
                .get("realitySettings")
                .ok_or_else(|| format!("{path}.streamSettings.realitySettings is required"))?;
            Security::Reality(RealityConfig {
                server_name: Arc::from(
                    r.get("serverName")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("{path}: reality serverName is required"))?,
                ),
                public_key: parse_reality_pubkey(
                    r.get("publicKey")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("{path}: reality publicKey is required"))?,
                )
                .map_err(|e| format!("{path}: {e}"))?,
                short_id: parse_hex(r.get("shortId").and_then(Value::as_str).unwrap_or(""))
                    .map_err(|e| format!("{path}: {e}"))?,
                fingerprint: parse_fingerprint(Some(r), path)?,
                spider_x: r.get("spiderX").and_then(Value::as_str).map(Arc::from),
                mldsa65_verify: parse_reality_mldsa65_verify(r, path)?,
            })
        }
        "shadowtls" => {
            let s = v
                .get("shadowtlsSettings")
                .ok_or_else(|| format!("{path}.streamSettings.shadowtlsSettings is required"))?;
            // Only v3 is implemented. sing-box also speaks v1/v2; a config for
            // either is rejected rather than silently treated as v3.
            let version = s.get("version").and_then(Value::as_u64).unwrap_or(3);
            if version != 3 {
                return Err(format!(
                    "{path}: ShadowTLS version {version} is unsupported, only 3"
                ));
            }
            let password = s
                .get("password")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .ok_or_else(|| format!("{path}: ShadowTLS password is required"))?;
            let tls = s.get("tls");
            let server_name = tls
                .and_then(|t| t.get("serverName"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}: ShadowTLS tls.serverName is required"))?;
            // ALPN is camouflage only (it rides the decoy ClientHello, not the
            // inner protocol). Default to what a browser offers so the hello
            // does not stand out when a config omits it.
            let alpn: Vec<Box<str>> = tls
                .and_then(|t| t.get("alpn"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(Box::from).collect())
                .unwrap_or_else(|| vec![Box::from("h2"), Box::from("http/1.1")]);
            Security::ShadowTls(ShadowTlsConfig {
                password: Arc::from(password),
                server_name: Arc::from(server_name),
                alpn,
            })
        }
        other => {
            return Err(format!(
                "{path}.streamSettings.security: unsupported {other:?}"
            ))
        }
    };

    if let Transport::Xhttp(settings) = &mut transport {
        if settings.xhttp_mode == XhttpMode::Auto {
            settings.xhttp_mode = if matches!(&security, Security::Reality(_)) {
                if settings.xhttp_download.is_some() {
                    XhttpMode::StreamUp
                } else {
                    XhttpMode::StreamOne
                }
            } else {
                XhttpMode::PacketUp
            };
        }
    }

    host_from_server_name(&mut transport, &security);

    let sockopt = v
        .get("sockopt")
        .map(|sockopt| parse_sockopt(sockopt, path))
        .transpose()?
        .unwrap_or_default();

    let evasion = match v.get("finalmask") {
        Some(f) => parse_finalmask(f, path)?,
        None => Evasion::default(),
    };

    let raw_http_header = parse_raw_http_header(v, path)?;

    Ok(StreamSettings {
        transport,
        security,
        sockopt,
        evasion,
        raw_http_header,
        direct: None,
    })
}

fn parse_ech_config(settings: Option<&Value>, path: &str) -> R<Option<EchConfig>> {
    let Some(settings) = settings else {
        return Ok(None);
    };

    let enabled = settings
        .get("enableECH")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // An empty string is how panels write "not set".
    let encoded = settings
        .get("echConfigList")
        .filter(|value| value.as_str().is_none_or(|text| !text.trim().is_empty()));
    let has_config = encoded.is_some_and(|value| !value.is_null());
    let inner_name = settings
        .get("echServerName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty());

    if !enabled && !has_config && inner_name.is_none() {
        return Ok(None);
    }

    if has_config && encoded.and_then(Value::as_str).is_none() {
        return Err(format!(
            "{path}.streamSettings.tlsSettings.echConfigList must be a base64 string"
        ));
    }

    let Some(text) = encoded.and_then(Value::as_str) else {
        // No list given: discovery from the HTTPS/SVCB record of the
        // configured public name. The runtime fills this bounded marker from
        // its managed resolver before constructing Rustls.
        return Ok(Some(EchConfig {
            config_list: Box::new([]),
            server_name: inner_name.map(Arc::from),
            query_name: None,
        }));
    };
    ech_from_text(text, inner_name)
        .map(Some)
        .map_err(|error| format!("{path}.streamSettings.tlsSettings.echConfigList {error}"))
}

/// The ECH setting as Xray and the share links write it: either the
/// base64 `ECHConfigList` itself, or a DNS query that finds it, such as
/// `cloudflare-ech.com+udp://1.1.1.1` or `https://1.1.1.1/dns-query`.
///
/// A query is not carried out here and its server is not used: the runtime
/// looks the list up with its own resolver, so the lookup follows the DNS
/// settings and cannot leak around them. Only the name before the `+` is
/// kept (`query_name`), because that is the part that changes the answer.
/// `inner` is the name to encrypt, when it differs from the TLS server name.
///
/// The error is the end of a sentence the caller starts ("... must not be
/// empty"), so each caller can say where the value came from.
pub(crate) fn ech_from_text(text: &str, inner: Option<&str>) -> Result<EchConfig, String> {
    let text = text.trim();
    let inner_name = inner.map(Arc::from);
    if text.contains("://") {
        let query_name = text
            .split_once('+')
            .map(|(name, _)| name)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            })
            .map(Arc::from);
        return Ok(EchConfig {
            config_list: Box::new([]),
            server_name: inner_name,
            query_name,
        });
    }
    if text.is_empty() {
        return Err("must not be empty".into());
    }

    use base64::Engine;
    // A `+` in a link's query can arrive as a space when something on the
    // way read it as a form.
    let text = text.replace(' ', "+");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&text))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&text))
        .map_err(|error| format!("is not valid base64: {error}"))?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err("must decode to 1..65536 bytes".into());
    }
    Ok(EchConfig {
        config_list: bytes.into_boxed_slice(),
        server_name: inner_name,
        query_name: None,
    })
}

/// Give a WebSocket, HTTPUpgrade or XHTTP transport that names no `Host` the
/// TLS server name as its Host, which is Xray's rule: the configured host,
/// else the SNI, else the address. Without it a config that reaches a
/// Cloudflare edge by IP, with the Worker's name only in the SNI, would send
/// the IP as the Host and be turned away.
pub(crate) fn host_from_server_name(transport: &mut Transport, security: &Security) {
    let Security::Tls(TlsConfig {
        server_name: Some(name),
        ..
    }) = security
    else {
        return;
    };
    if let Transport::WebSocket(config)
    | Transport::HttpUpgrade(config)
    | Transport::Xhttp(config) = transport
    {
        if config.host.is_none() {
            config.host = Some(name.clone());
        }
    }
}

/// The SHA-256 certificate pins of `pinnedPeerCertSha256` or a link's `pcs=`:
/// hex, comma or space separated, optionally with `:` between bytes. A value
/// that is not a 32-byte hash is an error rather than skipped, because a pin
/// dropped silently would leave the connection less protected than its author
/// asked for.
pub(crate) fn parse_cert_pins(text: &str) -> Result<Vec<[u8; 32]>, String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(|item| {
            let digits: Vec<u8> = item.bytes().filter(|b| *b != b':').collect();
            if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
                return Err(format!("{item:?} is not a 32-byte SHA-256 hash in hex"));
            }
            let mut hash = [0u8; 32];
            for (byte, pair) in hash.iter_mut().zip(digits.chunks(2)) {
                *byte =
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("0"), 16).unwrap_or(0);
            }
            Ok(hash)
        })
        .collect()
}

fn parse_raw_http_header(v: &Value, path: &str) -> R<Option<RawHttpHeader>> {
    let settings = v.get("rawSettings").or_else(|| v.get("tcpSettings"));
    let Some(header) = settings.and_then(|settings| settings.get("header")) else {
        return Ok(None);
    };
    let header_type = header.get("type").and_then(Value::as_str).unwrap_or("none");
    if header_type.is_empty() || header_type == "none" {
        return Ok(None);
    }
    if header_type != "http" {
        return Err(format!(
            "{path}.streamSettings.rawSettings.header.type {header_type:?} is not supported"
        ));
    }

    let request = header.get("request").unwrap_or(&Value::Null);
    let request_headers = parse_header_map(request.get("headers"));
    let request_path = request
        .get("path")
        .and_then(|value| value.as_array())
        .and_then(|paths| paths.iter().find_map(Value::as_str))
        .or_else(|| request.get("path").and_then(Value::as_str))
        .unwrap_or("/");
    let request = RawHttpRequest {
        version: Box::from(
            request
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("1.1"),
        ),
        method: Box::from(
            request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET"),
        ),
        path: Box::from(request_path),
        headers: request_headers,
    };

    let response: Option<Result<RawHttpResponse, String>> =
        header.get("response").map(|response| {
            let status_text = response
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("200");
            let status = status_text.parse::<u16>().map_err(|_| {
                format!("{path}.streamSettings.rawSettings.header.response.status is invalid")
            })?;
            Ok(RawHttpResponse {
                version: Box::from(
                    response
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or("1.1"),
                ),
                status,
                reason: Box::from(
                    response
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("OK"),
                ),
                headers: parse_header_map(response.get("headers")),
            })
        });
    let response = response.transpose()?;
    Ok(Some(RawHttpHeader { request, response }))
}

fn parse_header_map(value: Option<&Value>) -> BTreeMap<Box<str>, Box<str>> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|object| object.iter())
        .filter_map(|(name, value)| {
            let value = value.as_str().map(str::to_owned).or_else(|| {
                value
                    .as_array()?
                    .iter()
                    .find_map(Value::as_str)
                    .map(str::to_owned)
            })?;
            Some((Box::from(name.as_str()), Box::from(value)))
        })
        .collect()
}

fn parse_fingerprint(v: Option<&Value>, path: &str) -> R<Fingerprint> {
    let s = v
        .and_then(|t| t.get("fingerprint"))
        .and_then(Value::as_str)
        .unwrap_or("");
    Fingerprint::parse(s).ok_or_else(|| format!("{path}: unknown fingerprint {s:?}"))
}

fn parse_ws(v: Option<&Value>) -> WebSocketConfig {
    let raw_path = v
        .and_then(|w| w.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("/");
    let (path, early_data_len) = crate::share_link::extract_early_data(raw_path);

    let mut headers: BTreeMap<Box<str>, Box<str>> = BTreeMap::new();
    if let Some(h) = v.and_then(|w| w.get("headers")).and_then(Value::as_object) {
        for (k, val) in h {
            // `"Host": ""` is how panels say "use the server name"; sent as
            // it stands it would be an empty Host header.
            if let Some(s) = val.as_str().filter(|s| !s.is_empty()) {
                headers.insert(Box::from(k.as_str()), Box::from(s));
            }
        }
    }

    // `host` may live at the top level or inside headers.
    let host = v
        .and_then(|w| w.get("host"))
        .and_then(Value::as_str)
        .filter(|host| !host.is_empty())
        .map(Arc::from)
        .or_else(|| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, val)| Arc::from(val.as_ref()))
        });

    WebSocketConfig {
        path: Arc::from(path.as_str()),
        host,
        headers,
        early_data_len,
        xhttp_mode: XhttpMode::StreamOne,
        xhttp_http_version: XhttpHttpVersion::Http1,
        xhttp_download: None,
        xhttp: Default::default(),
        grpc_multi_path: None,
        grpc_multi: false,
    }
}

/// Build the gRPC request path from `serviceName`.
///
/// A gRPC URI is `/<service>/<method>`, not `/<service>`. Xray follows that
/// exactly: a plain `serviceName` becomes `/<name>/Tun`, and a name that
/// already starts with `/` is taken as a full custom path whose last segment is
/// the method. Emitting `/<name>` alone is self-consistent — two Zray peers
/// agree on it perfectly — and rejected by every real gRPC server.
/// A port as Xray accepts it: a JSON number or a numeric string, 1-65535.
/// Anything else is `None` — never a value truncated onto another port.
fn json_port(value: &Value) -> Option<u16> {
    let port = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(text) => text.trim().parse().ok()?,
        _ => return None,
    };
    u16::try_from(port).ok().filter(|port| *port != 0)
}

/// The single-stream (`Tun`) path of a `serviceName`, and the multi-stream
/// (`TunMulti`) one when it is a different path (Xray's `getTunStreamName` and
/// `getTunMultiStreamName`): a plain name has `Tun` and `TunMulti`; a custom
/// path `/p/single|multi` names both; `/p/name` is one method for both.
pub(crate) fn grpc_paths(service: &str) -> (String, Option<String>) {
    let service = service.trim();
    if service.is_empty() {
        return ("/Tun".into(), Some("/TunMulti".into()));
    }
    let Some(custom) = service.strip_prefix('/') else {
        let name = service.trim_matches('/');
        return (format!("/{name}/Tun"), Some(format!("/{name}/TunMulti")));
    };
    // Custom path form: the final segment names the stream, and an optional
    // `|` separates the single and multiplexed stream names.
    let (prefix, ending) = match custom.rfind('/') {
        Some(index) => (&custom[..index], &custom[index + 1..]),
        None => ("", custom),
    };
    let join = |method: &str| {
        if prefix.is_empty() {
            format!("/{method}")
        } else {
            format!("/{prefix}/{method}")
        }
    };
    let mut names = ending.split('|');
    let single = names.next().unwrap_or(ending);
    (join(single), names.next().map(join))
}

fn parse_grpc(v: Option<&Value>) -> WebSocketConfig {
    let mut config = parse_ws(v);
    let service = v
        .and_then(|settings| settings.get("serviceName"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (single, multi) = grpc_paths(service);
    config.path = Arc::from(single);
    config.grpc_multi_path = multi.map(Arc::from);
    config.grpc_multi = v
        .and_then(|settings| settings.get("multiMode"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if config.host.is_none() {
        config.host = v
            .and_then(|settings| settings.get("authority"))
            .and_then(Value::as_str)
            .map(Arc::from);
    }
    config
}

/// A stream's XHTTP settings object: `xhttpSettings`, or `splithttpSettings`,
/// the name older panels and clients still write for the same transport.
fn xhttp_settings(stream: &Value) -> Option<&Value> {
    stream
        .get("xhttpSettings")
        .or_else(|| stream.get("splithttpSettings"))
}

fn parse_xhttp(v: Option<&Value>, stream: &Value, path: &str) -> R<WebSocketConfig> {
    let mut config = parse_ws(v);
    config.xhttp_mode = match v
        .and_then(|settings| settings.get("mode"))
        .and_then(Value::as_str)
    {
        Some(mode) => XhttpMode::parse(mode)
            .ok_or_else(|| format!("{path}.streamSettings.xhttpSettings.mode is invalid"))?,
        None => XhttpMode::Auto,
    };

    // Xray's `SplitHTTPConfig.Build`: `extra` replaces every setting except
    // host, path and mode.
    let outer = v.and_then(Value::as_object).cloned().unwrap_or_default();
    let effective = crate::xhttp::effective_object(&outer)
        .map_err(|error| format!("{path}.streamSettings.xhttpSettings: {error}"))?;
    if outer.contains_key("extra") {
        config.headers = effective
            .get("headers")
            .and_then(Value::as_object)
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(k, v)| Some((Box::from(k.as_str()), Box::from(v.as_str()?))))
                    .collect()
            })
            .unwrap_or_default();
    }
    config.xhttp = crate::xhttp::parse_settings(&effective, config.xhttp_mode)
        .map_err(|error| format!("{path}.streamSettings.{error}"))?;

    let explicit_version = v
        .and_then(|settings| settings.get("httpVersion"))
        .and_then(Value::as_str);
    config.xhttp_http_version = match explicit_version {
        None => {
            let security = stream.get("security").and_then(Value::as_str).unwrap_or("");
            let alpn: Vec<&str> = stream
                .get("tlsSettings")
                .and_then(|tls| tls.get("alpn"))
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            xray_http_version(security, &alpn)
        }
        Some("1" | "1.1" | "h1" | "http/1.1") => XhttpHttpVersion::Http1,
        Some("2" | "h2" | "http/2") => XhttpHttpVersion::Http2,
        Some("3" | "h3" | "http/3") => XhttpHttpVersion::Http3,
        Some(other) => {
            return Err(format!(
                "{path}.streamSettings.xhttpSettings.httpVersion: unsupported {other:?}"
            ))
        }
    };
    if config.xhttp_http_version == XhttpHttpVersion::Http3
        && !matches!(
            config.xhttp_mode,
            XhttpMode::StreamOne | XhttpMode::StreamUp | XhttpMode::PacketUp
        )
    {
        return Err(format!(
            "{path}.streamSettings.xhttpSettings.mode: HTTP/3 supports stream-one, stream-up, or packet-up"
        ));
    }
    config.xhttp_download = effective
        .get("downloadSettings")
        .map(|download| parse_xhttp_download(download, path).map(Box::new))
        .transpose()?;
    Ok(config)
}

/// Xray's `decideHTTPVersion`: REALITY is HTTP/2; TLS is HTTP/2 unless the
/// ALPN list is exactly `http/1.1` or `h3`; no TLS is HTTP/1.1.
pub(crate) fn xray_http_version(security: &str, alpn: &[&str]) -> XhttpHttpVersion {
    match security {
        "reality" => XhttpHttpVersion::Http2,
        "tls" => match alpn {
            ["http/1.1"] => XhttpHttpVersion::Http1,
            ["h3"] => XhttpHttpVersion::Http3,
            _ => XhttpHttpVersion::Http2,
        },
        _ => XhttpHttpVersion::Http1,
    }
}

pub(crate) fn parse_xhttp_download(v: &Value, path: &str) -> R<XhttpDownloadConfig> {
    if xhttp_settings(v)
        .and_then(|settings| settings.get("downloadSettings"))
        .is_some()
    {
        return Err(format!(
            "{path}.streamSettings.xhttpSettings.downloadSettings: nested downloadSettings are not allowed"
        ));
    }
    let address = v.get("address").and_then(Value::as_str).ok_or_else(|| {
        format!("{path}.streamSettings.xhttpSettings.downloadSettings.address is required")
    })?;
    let port = v
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| {
            format!("{path}.streamSettings.xhttpSettings.downloadSettings.port is invalid")
        })? as u16;
    let network = v.get("network").and_then(Value::as_str).unwrap_or("xhttp");
    if !matches!(network, "xhttp" | "splithttp") {
        return Err(format!(
            "{path}.streamSettings.xhttpSettings.downloadSettings.network must be xhttp"
        ));
    }
    let mut diagnostics = ParseOutput::default();
    let stream = parse_stream(
        v,
        &format!("{path}.streamSettings.xhttpSettings.downloadSettings"),
        &mut diagnostics,
    )?;
    if !matches!(stream.transport, Transport::Xhttp(_)) {
        return Err(format!(
            "{path}.streamSettings.xhttpSettings.downloadSettings must compile to XHTTP"
        ));
    }
    Ok(XhttpDownloadConfig {
        address: Address::parse_host(address),
        port,
        stream: Box::new(stream),
    })
}

fn parse_sockopt(v: &Value, path: &str) -> R<Sockopt> {
    let domain_strategy = match v.get("domainStrategy") {
        Some(value) => {
            let value = value.as_str().ok_or_else(|| {
                format!("{path}.streamSettings.sockopt.domainStrategy must be a string")
            })?;
            DomainStrategy::parse(value).ok_or_else(|| {
                format!(
                    "{path}.streamSettings.sockopt.domainStrategy has unsupported domain strategy {value:?}"
                )
            })?
        }
        None => DomainStrategy::AsIs,
    };
    Ok(Sockopt {
        domain_strategy,
        tcp_fast_open: v
            .get("tcpFastOpen")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        happy_eyeballs: v.get("happyEyeballs").map(|h| HappyEyeballs {
            try_delay: std::time::Duration::from_millis(
                h.get("tryDelayMs").and_then(Value::as_u64).unwrap_or(250),
            ),
            prioritize_ipv6: h
                .get("prioritizeIPv6")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            // Xray's default interleave is 1 (strict alternation).
            interleave: h
                .get("interleave")
                .and_then(Value::as_u64)
                .map_or(1, |value| u32::try_from(value).unwrap_or(u32::MAX)),
            max_concurrent: h
                .get("maxConcurrentTry")
                .and_then(Value::as_u64)
                .map_or(4, |value| u32::try_from(value).unwrap_or(u32::MAX)),
        }),
        dialer_proxy: v.get("dialerProxy").and_then(Value::as_str).map(Arc::from),
        mark: v
            .get("mark")
            .and_then(Value::as_u64)
            .and_then(|m| u32::try_from(m).ok()),
        // Trimmed and dropped when blank, so an empty `tcpCongestion` means
        // "system default" rather than a request to set a sockopt named "".
        tcp_congestion: v
            .get("tcpCongestion")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(Arc::from),
        bind_interface: v.get("interface").and_then(Value::as_str).map(Arc::from),
        keepalive: parse_keepalive_pair(v),
        user_timeout_ms: v
            .get("tcpUserTimeout")
            .and_then(Value::as_u64)
            .and_then(|ms| u32::try_from(ms).ok())
            .filter(|ms| *ms > 0),
        window_clamp: v
            .get("tcpWindowClamp")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0),
        max_seg: v
            .get("tcpMaxSeg")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0),
        mptcp: v.get("tcpMptcp").and_then(Value::as_bool).unwrap_or(false),
        v6_only: v.get("V6Only").and_then(Value::as_bool),
        tproxy: match v.get("tproxy").and_then(Value::as_str) {
            None => Tproxy::Off,
            Some(name) => Tproxy::parse(name).ok_or_else(|| {
                format!(
                    "{path}.sockopt.tproxy: {name:?} is not \"off\", \"redirect\" or \"tproxy\""
                )
            })?,
        },
        bind_address: None,
        custom: parse_custom_sockopt(v, path)?,
    })
}

/// `customSockopt`: `[{"system", "network", "level", "opt", "value", "type"}]`.
/// `level` and `opt` are numbers (as text or as JSON numbers); `type` is
/// `int` or `str`.
fn parse_custom_sockopt(v: &Value, path: &str) -> R<Vec<zero_core::custom_sockopt::CustomSockopt>> {
    use zero_core::custom_sockopt::{CustomSockopt, CustomValue};
    let Some(list) = v.get("customSockopt").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let number = |value: Option<&Value>, what: &str, at: usize| -> R<Option<i32>> {
        match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
            Some(Value::String(text)) => text.trim().parse().map(Some).map_err(|_| {
                format!("{path}.sockopt.customSockopt[{at}].{what} {text:?} is not a number")
            }),
            Some(Value::Number(number)) => number
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| {
                    format!("{path}.sockopt.customSockopt[{at}].{what} is out of range")
                }),
            Some(_) => Err(format!(
                "{path}.sockopt.customSockopt[{at}].{what} must be a number"
            )),
        }
    };
    let mut options = Vec::new();
    for (at, entry) in list.iter().enumerate() {
        let text = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or("");
        let opt = number(entry.get("opt"), "opt", at)?
            .ok_or_else(|| format!("{path}.sockopt.customSockopt[{at}].opt is required"))?;
        let value = match text("type") {
            "int" => CustomValue::Int(number(entry.get("value"), "value", at)?.unwrap_or(0)),
            "str" => CustomValue::Bytes(text("value").as_bytes().to_vec()),
            other => {
                return Err(format!(
                    "{path}.sockopt.customSockopt[{at}].type {other:?} is not int or str"
                ))
            }
        };
        options.push(CustomSockopt {
            system: Some(text("system").to_string()).filter(|system| !system.is_empty()),
            network: text("network").to_string(),
            // Xray's default level is TCP.
            level: number(entry.get("level"), "level", at)?.unwrap_or(6),
            opt,
            value,
        });
    }
    Ok(options)
}

/// `tcpKeepAliveIdle` and `tcpKeepAliveInterval`, in Xray's convention: a
/// positive number is seconds, zero or absent is the default (45), and a
/// negative number turns keepalive off. `None` when neither is set.
fn parse_keepalive_pair(v: &Value) -> Option<(u32, u32)> {
    let get = |key: &str| v.get(key).and_then(Value::as_i64);
    let (idle, interval) = (get("tcpKeepAliveIdle"), get("tcpKeepAliveInterval"));
    if idle.is_none() && interval.is_none() {
        return None;
    }
    if idle.is_some_and(|n| n < 0) || interval.is_some_and(|n| n < 0) {
        return Some((0, 0));
    }
    let seconds = |n: Option<i64>| match n {
        Some(n) if n > 0 => u32::try_from(n).unwrap_or(u32::MAX),
        _ => 45,
    };
    Some((seconds(idle), seconds(interval)))
}

/// The TCP fragmentation a share link's `fm=` carries: Xray's `finalmask`
/// object as JSON text, one or two stacked `fragment` masks. Anything else in
/// it (UDP noise, keepalive) is not part of what a link can ask for. `None`
/// when the text is not that.
pub(crate) fn fragment_from_finalmask(text: &str) -> Option<Evasion> {
    let value: Value = serde_json::from_str(text.trim()).ok()?;
    let parsed = parse_finalmask(&value, "fm").ok()?;
    parsed.tcp_fragment.as_ref()?;
    Some(Evasion {
        tcp_fragment: parsed.tcp_fragment,
        tcp_fragment_under: parsed.tcp_fragment_under,
        ..Evasion::default()
    })
}

/// `streamSettings.finalmask` — Xray's current fragment/noise schema.
fn parse_finalmask(v: &Value, path: &str) -> R<Evasion> {
    let mut ev = Evasion::default();

    if let Some(tcp) = v.get("tcp").and_then(Value::as_array) {
        for (i, entry) in tcp.iter().enumerate() {
            let ty = entry.get("type").and_then(Value::as_str).unwrap_or("");
            let s = entry.get("settings");
            match ty {
                // Xray wraps the connection in each mask in turn, so a later
                // entry sits on top of an earlier one and sees the writes
                // first; the earlier one cuts up what it lets through.
                "fragment" => {
                    let mask = parse_fragment(s, &format!("{path}.finalmask.tcp[{i}]"))?;
                    if ev.tcp_fragment_under.is_some() {
                        return Err(format!(
                            "{path}.finalmask.tcp[{i}]: at most two fragment masks can be stacked"
                        ));
                    }
                    ev.tcp_fragment_under = ev.tcp_fragment.replace(mask);
                }
                "keepalive" => {
                    ev.keepalive = Some(parse_keepalive(s, &format!("{path}.finalmask.tcp[{i}]"))?)
                }
                other => {
                    return Err(format!(
                        "{path}.finalmask.tcp[{i}].type: unsupported mask {other:?}"
                    ))
                }
            }
        }
    }

    if let Some(udp) = v.get("udp").and_then(Value::as_array) {
        for (i, entry) in udp.iter().enumerate() {
            let ty = entry.get("type").and_then(Value::as_str).unwrap_or("");
            match ty {
                "noise" => {
                    let noises = entry
                        .get("settings")
                        .and_then(|s| s.get("noise"))
                        .and_then(Value::as_array)
                        .map(|a| a.as_slice())
                        .unwrap_or(&[]);
                    for n in noises {
                        ev.udp_noise.push(parse_noise(n)?);
                    }
                }
                "salamander" => {
                    let here = format!("{path}.finalmask.udp[{i}]");
                    let settings = entry.get("settings");
                    let password = settings
                        .and_then(|s| s.get("password"))
                        .and_then(Value::as_str)
                        .filter(|password| password.len() >= 4)
                        .ok_or_else(|| {
                            format!("{here}.settings.password must be at least 4 bytes")
                        })?;
                    // Gecko padding changes datagram sizes; without it the
                    // two ends disagree, so it is refused, not ignored.
                    let packet_size = settings.and_then(|s| s.get("packetSize"));
                    if packet_size.is_some_and(|size| match size {
                        Value::String(text) => !text.trim().is_empty(),
                        Value::Number(number) => number.as_u64() != Some(0),
                        Value::Null => false,
                        _ => true,
                    }) {
                        return Err(format!(
                            "{here}.settings.packetSize: Gecko packet-size padding is not supported"
                        ));
                    }
                    ev.udp_salamander = Some(password.into());
                }
                "udphop" => {
                    ev.udp_hop = Some(parse_udp_hop(
                        entry.get("settings"),
                        &format!("{path}.finalmask.udp[{i}]"),
                    )?)
                }
                "mkcp-legacy" | "header-custom" | "sudoku" | "xdns" | "xicmp" | "realm" => {
                    return Err(format!(
                        "{path}.finalmask.udp[{i}].type: the {ty:?} mask is not implemented"
                    ))
                }
                other => {
                    return Err(format!(
                        "{path}.finalmask.udp[{i}].type: unsupported mask {other:?}"
                    ))
                }
            }
        }
    }

    if let Some(params) = v.get("quicParams").filter(|params| !params.is_null()) {
        let here = format!("{path}.finalmask.quicParams");
        ev.quic = Some(parse_quic_params(params, &here)?);
        // The hop plan may be written here too (`udpHop`); it is the same
        // plan the `udphop` mask makes, and naming both is a conflict.
        if let Some(hop) = params.get("udpHop").filter(|hop| !hop.is_null()) {
            if ev.udp_hop.is_some() {
                return Err(format!("{here}.udpHop conflicts with a udphop mask"));
            }
            let ports = hop.get("ports").map(parse_hop_ports).unwrap_or_default();
            if ports.is_empty() {
                return Err(format!("{here}.udpHop.ports must list at least one port"));
            }
            let interval_secs = match hop.get("interval") {
                None | Some(Value::Null) => (30, 30),
                Some(value) => parse_secs_range(value, 5, &format!("{here}.udpHop.interval"))?,
            };
            ev.udp_hop = Some(UdpHop {
                ports,
                interval_secs,
            });
        }
    }

    Ok(ev)
}

/// `udphop` settings: `remotePorts` (a list or ranges, `"20000-50000,443"`)
/// and `interval` seconds (a number or `"5-10"`, at least 5). Only the mode
/// that Zray can carry out on its own is accepted, `intervallocal`; the
/// others rely on the firewall to do part of the work.
fn parse_udp_hop(settings: Option<&Value>, path: &str) -> R<UdpHop> {
    let settings = settings.ok_or_else(|| format!("{path}.settings is required for udphop"))?;
    let mode = settings
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("intervallocal");
    for part in mode.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part != "intervallocal" {
            return Err(format!(
                "{path}.settings.mode: {part:?} needs firewall support that Zray does not set up; use intervallocal"
            ));
        }
    }
    if settings
        .get("remoteIPs")
        .and_then(Value::as_array)
        .is_some_and(|ips| {
            ips.iter()
                .any(|ip| ip.as_str().is_some_and(|ip| !ip.is_empty()))
        })
    {
        return Err(format!(
            "{path}.settings.remoteIPs: hopping between addresses is not supported"
        ));
    }
    let ports = settings
        .get("remotePorts")
        .map(parse_hop_ports)
        .unwrap_or_default();
    if ports.is_empty() {
        return Err(format!(
            "{path}.settings.remotePorts must list at least one port"
        ));
    }
    let interval_secs = match settings.get("interval") {
        None | Some(Value::Null) => (30, 30),
        Some(value) => parse_secs_range(value, 5, &format!("{path}.settings.interval"))?,
    };
    Ok(UdpHop {
        ports,
        interval_secs,
    })
}

/// Ports as `"443"`, `"11,13,15-17"`, `"11;13"`, a number, or a list of those.
fn parse_hop_ports(value: &Value) -> Vec<routing::PortRange> {
    match value {
        Value::String(text) => text
            .split([',', ';'])
            .filter_map(routing::PortRange::parse)
            .filter(|range| range.start <= range.end)
            .collect(),
        other => parse_port_list(other),
    }
}

/// Seconds as a number or `"min-max"`, neither below `floor`.
fn parse_secs_range(value: &Value, floor: u32, what: &str) -> R<(u32, u32)> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_string(),
        _ => return Err(format!("{what} must be seconds, or a range like \"5-10\"")),
    };
    let (low, high) = text.split_once('-').unwrap_or((&text, &text));
    let number = |part: &str| -> R<u32> {
        part.trim()
            .parse::<u32>()
            .ok()
            .filter(|n| *n >= floor)
            .ok_or_else(|| format!("{what} must be at least {floor} seconds"))
    };
    let (low, high) = (number(low)?, number(high)?);
    if low > high {
        return Err(format!("{what} must be written smallest first"));
    }
    Ok((low, high))
}

/// A rate such as `"60 mbps"`, `"100kb"`, `"1g"` or a bare number, as bytes
/// per second. Units are bits per second (`bps`, `kbps`, `mbps`, `gbps`, or
/// without the `ps`) counted in powers of 1024, as Xray counts them (so
/// `"20 mbps"` is 2,621,440 bytes per second); a bare number is bits per
/// second too. Zero means none.
fn parse_rate(value: &Value, what: &str) -> R<u64> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_ascii_lowercase(),
        Value::Null => return Ok(0),
        _ => return Err(format!("{what} must be a rate like \"60 mbps\"")),
    };
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("{what} must be a rate like \"60 mbps\""))?;
    let factor = match unit.trim() {
        "" | "b" | "bps" => 1.0,
        "k" | "kb" | "kbps" => 1024.0,
        "m" | "mb" | "mbps" => 1024.0 * 1024.0,
        "g" | "gb" | "gbps" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tbps" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("{what}: unknown rate unit {other:?}")),
    };
    let bits = number * factor;
    if bits != 0.0 && bits < 65_535.0 {
        return Err(format!("{what} must be at least 65535 bps"));
    }
    Ok((bits / 8.0) as u64)
}

fn parse_quic_params(v: &Value, path: &str) -> R<QuicParams> {
    let number = |key: &str, low: u64, high: u64| -> R<Option<u32>> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .filter(|n| (low..=high).contains(n))
                .map(|n| Some(n as u32))
                .ok_or_else(|| format!("{path}.{key} must be a number from {low} to {high}")),
        }
    };
    let congestion = match v.get("congestion").and_then(Value::as_str).unwrap_or("") {
        "" => QuicCongestion::Default,
        "reno" => QuicCongestion::Reno,
        "bbr" => QuicCongestion::Bbr,
        "brutal" => QuicCongestion::Brutal,
        "force-brutal" => QuicCongestion::ForceBrutal,
        other => return Err(format!("{path}.congestion: unknown algorithm {other:?}")),
    };
    let rate = |key: &str| -> R<u64> {
        v.get(key)
            .map_or(Ok(0), |value| parse_rate(value, &format!("{path}.{key}")))
    };
    Ok(QuicParams {
        congestion,
        up_bytes_per_sec: rate("brutalUp")?,
        down_bytes_per_sec: rate("brutalDown")?,
        init_stream_window: number("initStreamReceiveWindow", 16 * 1024, u32::MAX as u64)?,
        max_stream_window: number("maxStreamReceiveWindow", 16 * 1024, u32::MAX as u64)?,
        init_connection_window: number("initConnectionReceiveWindow", 16 * 1024, u32::MAX as u64)?,
        max_connection_window: number("maxConnectionReceiveWindow", 16 * 1024, u32::MAX as u64)?,
        max_idle_secs: number("maxIdleTimeout", 4, 120)?,
        keep_alive_secs: number("keepAlivePeriod", 2, 60)?,
        disable_mtu_discovery: v
            .get("disablePathMTUDiscovery")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_incoming_streams: number("maxIncomingStreams", 8, u32::MAX as u64)?,
    })
}

/// Xray's older Freedom schema put the same mechanisms under the outbound's
/// own settings object. Keep it source-compatible while compiling both forms
/// into the one runtime evasion model.
fn parse_legacy_freedom_evasion(settings: Option<&Value>, path: &str) -> R<Evasion> {
    let Some(settings) = settings else {
        return Ok(Evasion::default());
    };
    let mut evasion = Evasion::default();
    if settings.get("fragment").is_some() {
        evasion.tcp_fragment = Some(parse_fragment(
            settings.get("fragment"),
            &format!("{path}.settings.fragment"),
        )?);
    }
    if let Some(noises) = settings.get("noises").and_then(Value::as_array) {
        for noise in noises {
            evasion.udp_noise.push(parse_noise(noise)?);
        }
    }
    if settings.get("keepalive").is_some() {
        evasion.keepalive = Some(parse_keepalive(
            settings.get("keepalive"),
            &format!("{path}.keepalive"),
        )?);
    }
    // SNI spoofing: a decoy ClientHello carrying an allow-listed SNI is injected
    // outside the TCP window so a passive DPI parser reads the decoy while the
    // real peer discards it. Off unless a fake SNI is named.
    if let Some(spoof) = settings.get("sniSpoof") {
        evasion.sni_desync = Some(parse_sni_spoof(spoof, &format!("{path}.sniSpoof"))?);
    }
    Ok(evasion)
}

/// `{"fakeSni": "www.example.com", "sequence": 0, "method": "decoy"}` — the
/// decoy SNI (and the optional out-of-window sequence) for a fake
/// ClientHello, or `{"method": "urgent"}` for the urgent-byte method (or
/// `"fastopen"` for the hello in the SYN, `"record"` for another version in the
/// first record header, `"empty"` for an empty record ahead of the hello), which have no decoy and so need no `fakeSni`. Without `method` the device
/// decides (`SniMethod::Auto`).
///
/// `fakeSni` accepts `?` (a letter), `#` (a digit) and `*` (either), drawn
/// once per connection, so one process never spells the same decoy name twice.
///
/// `fooling` says how the decoy is kept from the server: `md5`, `ttl`, or
/// `auto` (MD5 where the kernel has it). `ttl` is the hop limit for a decoy
/// that has to expire on the way; `"fooling": "ttl"` without one takes 8.
/// The hop limit a TTL decoy takes when its configuration names none: the
/// number the other userspace tools ship.
const DEFAULT_DECOY_TTL: u8 = 8;

fn parse_sni_spoof(value: &Value, path: &str) -> R<SniDesyncConfig> {
    let method = match value.get("method").and_then(Value::as_str) {
        None | Some("auto") => crate::model::SniMethod::Auto,
        Some("decoy") => crate::model::SniMethod::Decoy,
        Some("urgent") => crate::model::SniMethod::Urgent,
        Some("fastopen" | "tfo") => crate::model::SniMethod::FastOpen,
        Some("record" | "recordversion") => crate::model::SniMethod::Record,
        Some("empty" | "emptyrecord") => crate::model::SniMethod::EmptyRecord,
        Some(other) => {
            return Err(format!(
            "{path}.method must be auto, decoy, urgent, record, empty or fastopen, not {other:?}"
        ))
        }
    };
    let fake_sni = match value
        .get("fakeSni")
        .or_else(|| value.get("fake_sni"))
        .and_then(Value::as_str)
    {
        Some(name) => name,
        None if matches!(
            method,
            crate::model::SniMethod::Urgent
                | crate::model::SniMethod::FastOpen
                | crate::model::SniMethod::Record
                | crate::model::SniMethod::EmptyRecord
        ) =>
        {
            "www.speedtest.net"
        }
        None => return Err(format!("{path}.fakeSni is required")),
    };
    // Match the injector's own bound (zero_evasion::build_fake_client_hello):
    // 1..=219 visible bytes, so the decoy hello stays a fixed 517-byte packet.
    if fake_sni.is_empty() || fake_sni.len() > 219 || !fake_sni.bytes().all(|b| b > 0x20) {
        return Err(format!("{path}.fakeSni must be 1..=219 visible bytes"));
    }
    let sequence = value
        .get("sequence")
        .and_then(Value::as_u64)
        .map(|s| s as u32)
        .unwrap_or(0);
    let fooling = match value.get("fooling").and_then(Value::as_str) {
        None | Some("auto") => crate::model::DecoyFooling::Auto,
        Some("md5") => crate::model::DecoyFooling::Md5,
        Some("ttl") => crate::model::DecoyFooling::Ttl,
        Some(other) => {
            return Err(format!(
                "{path}.fooling must be auto, md5 or ttl, not {other:?}"
            ))
        }
    };
    let ttl = match value.get("ttl") {
        None => match fooling {
            crate::model::DecoyFooling::Ttl => DEFAULT_DECOY_TTL,
            _ => 0,
        },
        Some(ttl) => match ttl.as_u64() {
            Some(ttl @ 0..=255) => ttl as u8,
            _ => return Err(format!("{path}.ttl must be a hop count from 0 to 255")),
        },
    };
    if fooling == crate::model::DecoyFooling::Ttl && ttl == 0 {
        return Err(format!("{path}.ttl must be above zero for fooling \"ttl\""));
    }
    Ok(SniDesyncConfig {
        fake_sni: fake_sni.into(),
        sequence,
        method,
        fooling,
        ttl,
    })
}

/// Lay an outbound's own `evasion` block (`value`, when there is one) over
/// `evasion`: each part it names replaces that part, the rest is kept.
fn layer_evasion(evasion: &mut Evasion, value: Option<&Value>, path: &str) -> R<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let overlay = parse_link_evasion(value, path)?;
    if overlay.tcp_fragment.is_some() {
        evasion.tcp_fragment = overlay.tcp_fragment;
    }
    if !overlay.udp_noise.is_empty() {
        evasion.udp_noise = overlay.udp_noise;
    }
    if overlay.keepalive.is_some() {
        evasion.keepalive = overlay.keepalive;
    }
    if overlay.sni_desync.is_some() {
        evasion.sni_desync = overlay.sni_desync;
    }
    Ok(())
}

/// Evasion layered onto an outbound: `{"fragment": {...}, "noises": [...]}`.
/// Deliberately the same shape as the Freedom schema so there is one
/// spelling of these knobs across the config surface.
fn parse_link_evasion(value: &Value, path: &str) -> R<Evasion> {
    if !value.is_object() {
        return Err(format!("{path}.evasion must be an object"));
    }
    parse_legacy_freedom_evasion(Some(value), path)
}

/// `{"idle": "15s", "lifetime": "120s"}` — keepalive shaping.
///
/// `lifetime: 0` (or `"0s"`) means never retire, which is the right answer for
/// a network that collects idle flows but does not cap their age.
fn parse_keepalive(settings: Option<&Value>, path: &str) -> R<KeepaliveConfig> {
    let default = KeepaliveConfig::default();
    let idle_after = match settings.and_then(|s| s.get("idle").or_else(|| s.get("idleAfter"))) {
        Some(value) => parse_duration(value, &format!("{path}.idle"))?,
        None => default.idle_after,
    };
    if idle_after.is_zero() {
        return Err(format!("{path}.idle must be greater than zero"));
    }
    let max_flow_lifetime =
        match settings.and_then(|s| s.get("lifetime").or_else(|| s.get("maxFlowLifetime"))) {
            Some(value) => {
                let parsed = parse_duration(value, &format!("{path}.lifetime"))?;
                if parsed.is_zero() {
                    None
                } else {
                    Some(parsed)
                }
            }
            None => default.max_flow_lifetime,
        };
    if let Some(lifetime) = max_flow_lifetime {
        if lifetime <= idle_after {
            return Err(format!(
                "{path}: lifetime must exceed idle, or the carrier retires before it ever probes"
            ));
        }
    }
    Ok(KeepaliveConfig {
        idle_after,
        max_flow_lifetime,
    })
}

fn parse_fragment(s: Option<&Value>, path: &str) -> R<FragmentConfig> {
    let get = |k: &str| s.and_then(|s| s.get(k)).and_then(Value::as_str);

    let packets = match get("packets").unwrap_or("tlshello") {
        "tlshello" => FragmentPackets::TlsHello,
        "tlssni" => FragmentPackets::TlsSni,
        other => {
            let r = RangeU32::parse(other)
                .ok_or_else(|| format!("{path}: bad packets value {other:?}"))?;
            FragmentPackets::Range {
                from: r.min,
                to: r.max,
            }
        }
    };

    // Xray has used both `interval` and `delay` for this field.
    let delay_str = get("delay").or_else(|| get("interval")).unwrap_or("1");

    // Xray also takes lists, one entry per piece, the last entry repeating
    // for every piece after it: `"lengths": ["0", "104", "1"]` is an empty
    // TLS record, a piece of 104 bytes, and pieces of one byte from there.
    // The model keeps the leading zeros as a count, the last entry as
    // `length`, and whatever sits between them as `lead_lengths`.
    let list = |key: &str| -> R<Vec<&str>> {
        match s.and_then(|s| s.get(key)) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or_else(|| format!("{path}: {key} must be a list of strings"))
                })
                .collect(),
            Some(_) => Err(format!("{path}: {key} must be a list of strings")),
        }
    };
    let mut lengths = list("lengths")?
        .into_iter()
        .map(|entry| RangeU32::parse(entry).ok_or_else(|| format!("{path}: bad length {entry:?}")))
        .collect::<R<Vec<_>>>()?;
    let length = match lengths.pop() {
        Some(last) => Some(last),
        None => RangeU32::parse(get("length").unwrap_or("100-200")),
    }
    .filter(|range| range.min > 0)
    .ok_or_else(|| format!("{path}: bad length (the last one cannot be 0)"))?;
    let empty_records = lengths.iter().take_while(|range| range.max == 0).count();
    let lead_lengths = lengths.split_off(empty_records);
    // In `tlshello` a zero is an empty record. Cutting raw bytes it is a
    // piece of nothing, which Xray accepts and which does nothing.
    if packets != FragmentPackets::TlsHello
        && (empty_records > 0 || lead_lengths.iter().any(|r| r.min == 0))
    {
        return Err(format!(
            "{path}: a zero in lengths is an empty TLS record, which needs packets \"tlshello\""
        ));
    }
    let mut delays = list("delays")?
        .into_iter()
        .map(|entry| {
            RangeDuration::parse_millis(entry).ok_or_else(|| format!("{path}: bad delay {entry:?}"))
        })
        .collect::<R<Vec<_>>>()?;
    let delay = match delays.pop() {
        Some(last) => last,
        None => {
            RangeDuration::parse_millis(delay_str).ok_or_else(|| format!("{path}: bad delay"))?
        }
    };
    if lead_lengths.len() > 64 || delays.len() > 64 {
        return Err(format!("{path}: more than 64 entries in lengths or delays"));
    }

    Ok(FragmentConfig {
        packets,
        length,
        delay,
        max_split: RangeU32::parse(get("maxSplit").unwrap_or("0"))
            .ok_or_else(|| format!("{path}: bad maxSplit"))?,
        empty_records: u8::try_from(empty_records)
            .map_err(|_| format!("{path}: too many empty records"))?,
        lead_lengths,
        lead_delays: delays,
    })
}

fn parse_noise(v: &Value) -> R<NoiseConfig> {
    use base64::Engine;

    let delay = RangeDuration::parse_millis(v.get("delay").and_then(Value::as_str).unwrap_or("0"))
        .ok_or("bad noise delay")?;
    let count = v.get("count").and_then(Value::as_u64).unwrap_or(1) as u32;

    let kind = if let Some(rand_spec) = v.get("rand").and_then(Value::as_str) {
        let byte_range = v
            .get("randRange")
            .and_then(Value::as_str)
            .and_then(|r| {
                let (a, b) = r.split_once('-')?;
                Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
            })
            .unwrap_or((0u8, 255u8));
        NoiseKind::Rand {
            length: RangeU32::parse(rand_spec).ok_or("bad rand length")?,
            byte_range,
        }
    } else {
        let ty = v.get("type").and_then(Value::as_str).unwrap_or("rand");
        let packet = v.get("packet");
        match ty {
            "rand" => {
                let byte_range = v
                    .get("randRange")
                    .and_then(Value::as_str)
                    .and_then(|range| {
                        let (min, max) = range.split_once('-')?;
                        Some((min.trim().parse().ok()?, max.trim().parse().ok()?))
                    })
                    .unwrap_or((0, u8::MAX));
                NoiseKind::Rand {
                    length: RangeU32::parse(packet.and_then(Value::as_str).unwrap_or("0-0"))
                        .ok_or("noise rand packet length is invalid")?,
                    byte_range,
                }
            }
            "quic" => NoiseKind::Quic {
                length: RangeU32::parse(packet.and_then(Value::as_str).unwrap_or("5-10"))
                    .ok_or("noise quic packet length is invalid")?,
            },
            "str" => NoiseKind::Str(packet.and_then(Value::as_str).unwrap_or("").into()),
            "hex" => NoiseKind::Hex(
                parse_hex(packet.and_then(Value::as_str).unwrap_or(""))
                    .map_err(|e| format!("noise hex: {e}"))?,
            ),
            "base64" => NoiseKind::Base64(
                base64::engine::general_purpose::STANDARD
                    .decode(packet.and_then(Value::as_str).unwrap_or(""))
                    .map_err(|_| "noise base64 is invalid".to_string())?,
            ),
            "array" => {
                let bytes = match packet {
                    Some(Value::Array(a)) => a
                        .iter()
                        .filter_map(Value::as_u64)
                        .map(|n| n as u8)
                        .collect(),
                    Some(Value::String(s)) => s
                        .split(',')
                        .filter_map(|p| p.trim().parse::<u8>().ok())
                        .collect(),
                    _ => Vec::new(),
                };
                NoiseKind::Array(bytes)
            }
            other => return Err(format!("unsupported noise type {other:?}")),
        }
    };

    Ok(NoiseConfig { kind, delay, count })
}

/// `burstObservatory`: `subjectSelector` and `pingConfig.destination` /
/// `pingConfig.interval` become the observatory's selector, probe address and
/// probe interval. How many samples a round takes, and the timeout, are the
/// runtime's own.
fn parse_burst_observatory(v: &Value) -> R<ObservatoryConfig> {
    let ping = v.get("pingConfig");
    let mut translated = serde_json::Map::new();
    if let Some(selector) = v.get("subjectSelector") {
        translated.insert("subjectSelector".into(), selector.clone());
    }
    if let Some(destination) = ping.and_then(|p| p.get("destination")) {
        translated.insert("probeUrl".into(), destination.clone());
    }
    if let Some(interval) = ping.and_then(|p| p.get("interval")) {
        translated.insert("probeInterval".into(), interval.clone());
    }
    parse_observatory(&Value::Object(translated), "burstObservatory")
}

/// `policy.levels."0"`: `handshake`, `connIdle`, `uplinkOnly` and
/// `downlinkOnly`, in seconds. Other levels belong to accounts with that
/// level, which Zray's do not have; they, `system`, and `bufferSize` are
/// accepted and reported, not applied.
fn parse_policy(v: &Value, out: &mut ParseOutput) -> R<Policy> {
    let mut policy = Policy::default();
    let level0 = v.get("levels").and_then(|levels| levels.get("0"));
    if let Some(level) = level0 {
        let seconds = |key: &str| -> R<Option<std::time::Duration>> {
            match level.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value
                    .as_u64()
                    .map(|secs| Some(std::time::Duration::from_secs(secs)))
                    .ok_or_else(|| format!("policy.levels.0.{key} must be a number of seconds")),
            }
        };
        if let Some(handshake) = seconds("handshake")?.filter(|d| !d.is_zero()) {
            policy.handshake = handshake;
        }
        if let Some(idle) = seconds("connIdle")? {
            policy.conn_idle = idle;
        }
        let half = [seconds("uplinkOnly")?, seconds("downlinkOnly")?]
            .into_iter()
            .flatten()
            .max();
        if let Some(half) = half {
            policy.half_close = half;
        }
        if level.get("bufferSize").is_some() {
            out.note(
                "policy.levels.0.bufferSize",
                "accepted, not applied: relay buffers are sized by use",
            );
        }
    }
    if v.get("levels")
        .and_then(Value::as_object)
        .is_some_and(|levels| levels.keys().any(|key| key != "0"))
    {
        out.note(
            "policy.levels",
            "levels other than 0 are accepted, not applied: accounts have no level here",
        );
    }
    if v.get("system").is_some() {
        out.note(
            "policy.system",
            "accepted, not applied: the statistics switches have no counterpart here",
        );
    }
    Ok(policy)
}

fn parse_observatory(v: &Value, path: &str) -> R<ObservatoryConfig> {
    let object = v
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let probe_url: Arc<str> = object
        .get("probeUrl")
        .or_else(|| object.get("probeURL"))
        .and_then(Value::as_str)
        .unwrap_or("https://www.google.com/generate_204")
        .into();
    let parsed = url::Url::parse(&probe_url)
        .map_err(|error| format!("{path}.probeUrl is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(format!(
            "{path}.probeUrl must be an http(s) URL without user credentials"
        ));
    }
    let probe_interval = object
        .get("probeInterval")
        .map(|value| parse_duration(value, &format!("{path}.probeInterval")))
        .transpose()?
        .unwrap_or(std::time::Duration::from_secs(60));
    if !(std::time::Duration::from_secs(5)..=std::time::Duration::from_secs(86_400))
        .contains(&probe_interval)
    {
        return Err(format!("{path}.probeInterval must be between 5s and 24h"));
    }
    let subject_selector = match object.get("subjectSelector") {
        None => Vec::new(),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            vec![value.trim().into()]
        }
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .as_str()
                    .filter(|text| !text.trim().is_empty())
                    .map(|text| text.trim().into())
                    .ok_or_else(|| format!("{path}.subjectSelector[{index}] must be a string"))
            })
            .collect::<R<Vec<Box<str>>>>()?,
        Some(_) => return Err(format!("{path}.subjectSelector must be a string or array")),
    };
    let clean_ip = match object.get("cleanIp").or_else(|| object.get("cleanIP")) {
        None => None,
        Some(value) => Some(parse_clean_ip(value, &format!("{path}.cleanIp"))?),
    };
    Ok(ObservatoryConfig {
        probe_url,
        probe_interval,
        subject_selector: subject_selector.into_boxed_slice(),
        clean_ip,
    })
}

fn parse_assets(value: &Value, path: &str) -> R<AssetsConfig> {
    use std::time::Duration;

    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let defaults = AssetsConfig::default();

    let directory = match object.get("directory") {
        None => None,
        Some(Value::String(text)) if !text.trim().is_empty() => Some(Arc::from(text.trim())),
        Some(_) => return Err(format!("{path}.directory must be a non-empty string")),
    };

    let refresh_interval = object
        .get("refreshInterval")
        .map(|value| parse_duration(value, &format!("{path}.refreshInterval")))
        .transpose()?
        .unwrap_or(defaults.refresh_interval);
    if !(Duration::from_secs(60)..=Duration::from_secs(30 * 86_400)).contains(&refresh_interval) {
        return Err(format!("{path}.refreshInterval must be between 1m and 30d"));
    }
    let retry_interval = object
        .get("retryInterval")
        .map(|value| parse_duration(value, &format!("{path}.retryInterval")))
        .transpose()?
        .unwrap_or(defaults.retry_interval);
    if !(Duration::from_secs(30)..=refresh_interval).contains(&retry_interval) {
        return Err(format!(
            "{path}.retryInterval must be between 30s and refreshInterval"
        ));
    }
    let timeout = object
        .get("timeout")
        .map(|value| parse_duration(value, &format!("{path}.timeout")))
        .transpose()?
        .unwrap_or(defaults.timeout);
    if !(Duration::from_secs(1)..=Duration::from_secs(600)).contains(&timeout) {
        return Err(format!("{path}.timeout must be between 1s and 10m"));
    }
    let max_bytes = match object.get("maxBytes") {
        None => defaults.max_bytes,
        Some(value) => {
            let bytes = value
                .as_u64()
                .ok_or_else(|| format!("{path}.maxBytes must be a positive integer"))?;
            if !(1024..=512 * 1024 * 1024).contains(&bytes) {
                return Err(format!("{path}.maxBytes must be between 1KiB and 512MiB"));
            }
            bytes as usize
        }
    };
    let refresh_on_start = match object.get("refreshOnStart") {
        None => defaults.refresh_on_start,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(format!("{path}.refreshOnStart must be a boolean")),
    };
    let auto_update = match object.get("autoUpdate") {
        None => defaults.auto_update,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(format!("{path}.autoUpdate must be a boolean")),
    };

    let files = match object.get("files") {
        None => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| parse_asset_file(value, &format!("{path}.files[{index}]")))
            .collect::<R<Vec<AssetFile>>>()?,
        Some(_) => return Err(format!("{path}.files must be an array")),
    };
    // A file name is also a path component in the cache directory, so it is
    // constrained here rather than trusted from configuration.
    let mut seen = std::collections::BTreeSet::new();
    for file in &files {
        if !seen.insert(file.name.clone()) {
            return Err(format!("{path}.files has a duplicate name `{}`", file.name));
        }
    }

    Ok(AssetsConfig {
        directory,
        refresh_interval,
        retry_interval,
        max_bytes,
        timeout,
        refresh_on_start,
        auto_update,
        files: files.into_boxed_slice(),
    })
}

fn parse_asset_file(value: &Value, path: &str) -> R<AssetFile> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("{path}.name is required"))?;
    if name.contains('/')
        || name.contains('\\')
        || name.starts_with('.')
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!(
            "{path}.name must be a simple file name without path separators"
        ));
    }
    let kind = match object.get("kind").and_then(Value::as_str) {
        Some("geosite") => AssetFileKind::Geosite,
        Some("geoip") => AssetFileKind::Geoip,
        Some(other) => return Err(format!("{path}.kind `{other}` is not geosite or geoip")),
        None => return Err(format!("{path}.kind is required")),
    };
    let urls = match object.get("urls") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .as_str()
                    .ok_or_else(|| format!("{path}.urls[{index}] must be a string"))
            })
            .collect::<R<Vec<&str>>>()?,
        Some(_) => return Err(format!("{path}.urls must be a string or array")),
        None => Vec::new(),
    };
    let mut checked = Vec::with_capacity(urls.len());
    for url in urls {
        let parsed = url::Url::parse(url)
            .map_err(|error| format!("{path}.urls `{url}` is invalid: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(format!("{path}.urls `{url}` must be an http(s) URL"));
        }
        checked.push(Arc::from(url));
    }
    let sha256 = match object.get("sha256") {
        None => None,
        Some(Value::String(value)) => {
            let value = value.trim();
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("{path}.sha256 must be 64 hexadecimal characters"));
            }
            Some(Arc::from(value))
        }
        Some(_) => return Err(format!("{path}.sha256 must be a string")),
    };
    Ok(AssetFile {
        name: Arc::from(name),
        kind,
        urls: checked.into_boxed_slice(),
        sha256,
    })
}

fn parse_clean_ip(value: &Value, path: &str) -> R<CleanIpConfig> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let host: Arc<str> = object
        .get("host")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{path}.host is required"))?
        .trim()
        .into();
    if host.contains(['\r', '\n']) || host.len() > 253 {
        return Err(format!("{path}.host is not a valid HTTP Host value"));
    }
    let candidates = match object.get("candidates") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .as_str()
                    .ok_or_else(|| format!("{path}.candidates[{index}] must be a socket address"))
            })
            .collect::<R<Vec<_>>>()?,
        Some(_) => return Err(format!("{path}.candidates must be a string or array")),
        None => Vec::new(),
    };
    if candidates.len() > 256 {
        return Err(format!(
            "{path}.candidates must contain at most 256 entries"
        ));
    }
    let mut parsed = candidates
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .parse::<std::net::SocketAddr>()
                .map_err(|_| format!("{path}.candidates[{index}] is not a literal socket address"))
        })
        .collect::<R<Vec<_>>>()?;
    parsed.sort_unstable();
    parsed.dedup();
    let path_value: Arc<str> = object
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("/")
        .trim()
        .into();
    if !path_value.starts_with('/') || path_value.contains(['\r', '\n']) || path_value.len() > 2048
    {
        return Err(format!(
            "{path}.path must be an HTTP path without line breaks"
        ));
    }
    Ok(CleanIpConfig {
        candidates: parsed.into_boxed_slice(),
        host,
        path: path_value,
    })
}

fn parse_duration(value: &Value, path: &str) -> R<std::time::Duration> {
    if let Some(milliseconds) = value.as_u64() {
        return Ok(std::time::Duration::from_millis(milliseconds));
    }
    let text = value
        .as_str()
        .ok_or_else(|| format!("{path} must be milliseconds or a duration string"))?
        .trim();
    let (number, multiplier) = if let Some(value) = text.strip_suffix("ms") {
        (value, 1u64)
    } else if let Some(value) = text.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = text.strip_suffix('m') {
        (value, 60_000)
    } else if let Some(value) = text.strip_suffix('h') {
        (value, 3_600_000)
    } else {
        return Err(format!("{path} has no supported unit (ms, s, m, h)"));
    };
    let number = number
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{path} has an invalid duration"))?;
    Ok(std::time::Duration::from_millis(
        number.saturating_mul(multiplier),
    ))
}

// --------------------------------------------------------------- routing

fn parse_routing(v: &Value, out: &mut ParseOutput) -> R<Routing> {
    let domain_strategy = v
        .get("domainStrategy")
        .and_then(Value::as_str)
        .and_then(routing::DomainStrategy::parse)
        .unwrap_or_default();

    let rules = v
        .get("rules")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .enumerate()
                .map(|(i, r)| parse_rule(r, i, out))
                .collect::<R<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    // `leastLoad`'s own tuning (how many nodes to keep, the RTT ceiling, the
    // costs) is not read: Zray's least-load picks by recent failures and
    // rotates among equals.
    for (index, balancer) in v
        .get("balancers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let settings = balancer
            .get("strategy")
            .and_then(|strategy| strategy.get("settings"));
        if settings.is_some_and(|settings| settings.as_object().is_some_and(|map| !map.is_empty()))
        {
            out.note(
                format!("routing.balancers[{index}].strategy.settings"),
                "accepted, not applied: the balancer strategies take no tuning here",
            );
        }
    }

    let balancers = v
        .get("balancers")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(parse_balancer).collect::<R<Vec<_>>>())
        .transpose()?
        .unwrap_or_default();

    Ok(Routing {
        domain_strategy,
        rules: rules.into_boxed_slice(),
        balancers: balancers.into_boxed_slice(),
    })
}

fn parse_rule(v: &Value, idx: usize, out: &mut ParseOutput) -> R<Rule> {
    let path = format!("routing.rules[{idx}]");

    // Panels write `"outboundTag": ""` next to a `balancerTag`, as "not this".
    let target = if let Some(tag) = v
        .get("outboundTag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.is_empty())
    {
        RuleTarget::Outbound(Arc::from(tag))
    } else if let Some(tag) = v.get("balancerTag").and_then(Value::as_str) {
        RuleTarget::Balancer(Arc::from(tag))
    } else if let Some(resolver) = v.get("directVia").and_then(Value::as_str) {
        if resolver.trim().is_empty() {
            return Err(format!("{path}.directVia must name a resolver tag"));
        }
        RuleTarget::DirectVia {
            resolver: Arc::from(resolver),
        }
    } else {
        return Err(format!(
            "{path}: needs outboundTag, balancerTag, or directVia"
        ));
    };

    let mut rule = Rule::new(target);

    if let Some(a) = v
        .get("domain")
        .or_else(|| v.get("domains"))
        .and_then(Value::as_array)
    {
        rule.domains = a
            .iter()
            .filter_map(Value::as_str)
            .map(routing::DomainPattern::parse)
            .collect();
    }
    if let Some(a) = v.get("ip").and_then(Value::as_array) {
        rule.ips = a
            .iter()
            .filter_map(Value::as_str)
            .map(parse_ip_pattern)
            .collect();
    }
    if let Some(a) = v
        .get("source")
        .or_else(|| v.get("sourceIP"))
        .and_then(Value::as_array)
    {
        rule.source_ips = a
            .iter()
            .filter_map(Value::as_str)
            .map(parse_ip_pattern)
            .collect();
    }
    if let Some(p) = v.get("port") {
        rule.ports = parse_port_list(p);
    }
    if let Some(p) = v.get("sourcePort") {
        rule.source_ports = parse_port_list(p);
    }
    if let Some(n) = v.get("network").and_then(Value::as_str) {
        // A name that is neither tcp nor udp must not be dropped: a rule left
        // with no network at all would match every flow.
        rule.networks = n
            .split(',')
            .map(|s| match s.trim() {
                "tcp" => Ok(Network::Tcp),
                "udp" => Ok(Network::Udp),
                other => Err(format!("{path}.network: unknown network {other:?}")),
            })
            .collect::<R<_>>()?;
    }
    if let Some(a) = v.get("inboundTag").and_then(Value::as_array) {
        rule.inbound_tags = a.iter().filter_map(Value::as_str).map(Box::from).collect();
    }
    if let Some(a) = v.get("protocol").and_then(Value::as_array) {
        rule.protocols = a.iter().filter_map(Value::as_str).map(Box::from).collect();
    }
    if let Some(a) = v.get("process").and_then(Value::as_array) {
        rule.processes = a
            .iter()
            .filter_map(Value::as_str)
            .filter_map(routing::ProcessPattern::parse)
            .collect();
    }

    let strings = |key: &str| -> R<Vec<Box<str>>> {
        match v.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(Box::from)
                        .ok_or_else(|| format!("{path}.{key} must list strings"))
                })
                .collect(),
            Some(_) => Err(format!("{path}.{key} must be an array")),
        }
    };
    rule.users = strings("user")?;
    rule.local_ips = strings("localIP")?
        .iter()
        .map(|text| parse_ip_pattern(text))
        .collect();
    if let Some(p) = v.get("localPort") {
        rule.local_ports = parse_port_list(p);
    }
    if let Some(p) = v.get("vlessRoute") {
        rule.vless_routes = parse_port_list(p);
    }
    if let Some(attrs) = v.get("attrs") {
        let attrs = attrs
            .as_object()
            .ok_or_else(|| format!("{path}.attrs must be an object"))?;
        for (name, pattern) in attrs {
            let pattern = pattern
                .as_str()
                .ok_or_else(|| format!("{path}.attrs.{name} must be a string"))?;
            // Checked here so a typo is an error now, not a rule that never
            // matches.
            regex::Regex::new(pattern).map_err(|error| format!("{path}.attrs.{name}: {error}"))?;
            rule.attrs
                .push((name.to_ascii_lowercase().into(), pattern.into()));
        }
    }
    if v.get("webhook").is_some() {
        out.note(
            &path,
            "webhook is accepted but not sent; Zray does not call out when a rule matches",
        );
    }
    // Every key Xray defines for a rule is read above or below; anything else
    // is reported rather than dropped without a word.
    const KNOWN: &[&str] = &[
        "type",
        "ruleTag",
        "domain",
        "domains",
        "ip",
        "port",
        "sourcePort",
        "localPort",
        "network",
        "source",
        "sourceIP",
        "localIP",
        "user",
        "vlessRoute",
        "inboundTag",
        "protocol",
        "attrs",
        "outboundTag",
        "balancerTag",
        "process",
        "webhook",
        "domainMatcher",
        "directVia",
    ];
    if let Some(map) = v.as_object() {
        for key in map.keys().filter(|key| !KNOWN.contains(&key.as_str())) {
            out.note(&path, format!("unknown rule field {key:?} is ignored"));
        }
    }

    if rule.is_unconditional() {
        out.note(path, "rule has no selectors and will match every session");
    }

    Ok(rule)
}

fn parse_ip_pattern(s: &str) -> routing::IpPattern {
    if s == "geoip:private" || s == "private" {
        routing::IpPattern::Private
    } else if let Some(rest) = s.strip_prefix("geoip:") {
        routing::IpPattern::Geoip(rest.into())
    } else if let Some(c) = routing::ipnet_lite::Cidr::parse(s) {
        routing::IpPattern::Cidr(c)
    } else {
        // Unparseable entries become an impossible geoip tag rather than a
        // silently dropped rule component.
        routing::IpPattern::Geoip(s.into())
    }
}

fn parse_port_list(v: &Value) -> Vec<routing::PortRange> {
    match v {
        // Out-of-range numbers are dropped rather than wrapped onto an
        // unrelated port.
        Value::Number(n) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .map(|p| vec![routing::PortRange { start: p, end: p }])
            .unwrap_or_default(),
        Value::String(s) => s.split(',').filter_map(routing::PortRange::parse).collect(),
        Value::Array(a) => a.iter().flat_map(parse_port_list).collect(),
        _ => Vec::new(),
    }
}

fn parse_balancer(v: &Value) -> R<routing::Balancer> {
    Ok(routing::Balancer {
        tag: Arc::from(
            v.get("tag")
                .and_then(Value::as_str)
                .ok_or("balancer needs a tag")?,
        ),
        selector: v
            .get("selector")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(Box::from).collect())
            .unwrap_or_default(),
        strategy: v
            .get("strategy")
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            .and_then(routing::BalancerStrategy::parse)
            .unwrap_or_default(),
        fallback: v
            .get("fallbackTag")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty())
            .map(Arc::from),
    })
}

// ------------------------------------------------------------------- dns

/// DNS settings Xray has and Zray does not apply, named so a config that
/// leans on one learns it when checked. Each is accepted and ignored: none of
/// them changes whether a name resolves, only how fast, how fresh or how
/// private.
fn note_unapplied_dns(v: &Value, out: &mut ParseOutput) {
    const TOP: &[&str] = &[
        "clientIp",
        "serveStale",
        "serveExpiredTTL",
        "disableFallback",
        "disableFallbackIfMatch",
        "enableParallelQuery",
        "useSystemHosts",
        "script",
    ];
    const SERVER: &[&str] = &[
        "clientIp",
        "timeoutMs",
        "finalQuery",
        "serveStale",
        "serveExpiredTTL",
        "disableCache",
        "queryStrategy",
        "id",
    ];
    for key in TOP {
        if v.get(*key).is_some_and(|value| !value.is_null()) {
            out.note(
                format!("dns.{key}"),
                "accepted, not applied: Zray has no such resolver setting",
            );
        }
    }
    for (index, server) in v
        .get("servers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        for key in SERVER {
            if server.get(*key).is_some_and(|value| !value.is_null()) {
                out.note(
                    format!("dns.servers[{index}].{key}"),
                    "accepted, not applied: Zray has no such resolver setting",
                );
            }
        }
    }
}

fn parse_dns(v: &Value, out: &mut ParseOutput) -> R<DnsSettings> {
    note_unapplied_dns(v, out);
    let mut hosts = BTreeMap::new();
    if let Some(h) = v.get("hosts").and_then(Value::as_object) {
        for (k, val) in h {
            let value = match val {
                // Xray's sentinel for "answer as blocked".
                Value::String(s) if s.starts_with('#') => HostValue::Block,
                Value::String(s) => {
                    let a = Address::parse_host(s);
                    if a.is_ip() {
                        HostValue::Addresses(vec![a])
                    } else {
                        HostValue::Alias(s.as_str().into())
                    }
                }
                Value::Array(a) => HostValue::Addresses(
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(Address::parse_host)
                        .collect(),
                ),
                _ => continue,
            };
            hosts.insert(Box::from(k.as_str()), value);
        }
    }

    let servers = v
        .get("servers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .enumerate()
                .filter_map(|(i, s)| match parse_dns_server(s) {
                    Ok(srv) => Some(srv),
                    Err(e) => {
                        out.note(format!("dns.servers[{i}]"), e);
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // `dns.certificates`, in the same `usage: "verify"` form the outbound
    // path uses. Reusing the shape means an operator learns one rule, and
    // means neither place can quietly grow an `allowInsecure` equivalent.
    let trusted_roots = parse_dns_trusted_roots(v)?;

    Ok(DnsSettings {
        servers: servers.into_boxed_slice(),
        trusted_roots,
        hosts,
        query_strategy: v
            .get("queryStrategy")
            .and_then(Value::as_str)
            .and_then(QueryStrategy::parse)
            .unwrap_or_default(),
        // Zray's own key. Strict (the default) refuses the operating system's
        // resolver because on a client it would answer outside the tunnel; on a
        // server the system resolver is the right one, and the operator says so.
        leak_policy: match v.get("leakPolicy").and_then(Value::as_str) {
            Some("fallback") => LeakPolicy::Fallback,
            _ => LeakPolicy::Strict,
        },
        disable_cache: v
            .get("disableCache")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        tag: v.get("tag").and_then(Value::as_str).map(Arc::from),
    })
}

fn parse_dns_server(v: &Value) -> Result<DnsServer, String> {
    match v {
        Value::String(s) => Ok(DnsServer {
            endpoint: ResolverEndpoint::parse(s)
                .ok_or_else(|| format!("cannot parse resolver {s:?}"))?,
            domains: Vec::new(),
            expect_ips: Vec::new(),
            unexpect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        }),
        Value::Object(o) => {
            let addr = o
                .get("address")
                .and_then(Value::as_str)
                .ok_or("dns server object needs an address")?;
            let port = match o.get("port") {
                Some(value) => Some(json_port(value).ok_or("dns server port must be 1-65535")?),
                None => None,
            };
            let mut endpoint = ResolverEndpoint::parse(addr)
                .ok_or_else(|| format!("cannot parse resolver {addr:?}"))?;
            if let Some(p) = port {
                endpoint = override_port(endpoint, p);
            }
            Ok(DnsServer {
                endpoint,
                domains: o
                    .get("domains")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(routing::DomainPattern::parse)
                            .collect()
                    })
                    .unwrap_or_default(),
                expect_ips: o
                    .get("expectedIPs")
                    .or_else(|| o.get("expectIPs"))
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(parse_ip_pattern)
                            .collect()
                    })
                    .unwrap_or_default(),
                unexpect_ips: o
                    .get("unexpectedIPs")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(parse_ip_pattern)
                            .collect()
                    })
                    .unwrap_or_default(),
                skip_fallback: o
                    .get("skipFallback")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                tag: o.get("tag").and_then(Value::as_str).map(Arc::from),
            })
        }
        _ => Err("dns server must be a string or object".into()),
    }
}

fn override_port(e: ResolverEndpoint, port: u16) -> ResolverEndpoint {
    match e {
        ResolverEndpoint::Udp { address, .. } => ResolverEndpoint::Udp { address, port },
        ResolverEndpoint::Tcp { address, .. } => ResolverEndpoint::Tcp { address, port },
        ResolverEndpoint::Dot { address, .. } => ResolverEndpoint::Dot { address, port },
        other => other,
    }
}

// ----------------------------------------------------------------- helpers

fn parse_reality_pubkey(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| parse_hex(s).map_err(|_| base64::DecodeError::InvalidLength(0)))
        .map_err(|_| format!("reality publicKey is not base64 or hex: {s:?}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "reality publicKey must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_reality_private_key(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|_| "reality privateKey is not valid base64".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "reality privateKey must decode to 32 bytes".to_string())
}

fn parse_reality_mldsa65_verify(settings: &Value, path: &str) -> Result<Option<Box<[u8]>>, String> {
    let Some(encoded) = settings.get("mldsa65Verify").and_then(Value::as_str) else {
        return Ok(None);
    };
    if encoded.is_empty() {
        return Ok(None);
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| {
            format!("{path}.streamSettings.realitySettings.mldsa65Verify: invalid base64: {e}")
        })?;
    if bytes.len() != 1952 {
        return Err(format!(
            "{path}.streamSettings.realitySettings.mldsa65Verify must decode to 1952 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(Some(bytes.into_boxed_slice()))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("bad hex: {s:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_with_non_ascii_text_is_an_error_not_a_panic() {
        assert!(parse_hex("a…").is_err());
        assert!(parse_hex("\u{e9}\u{e9}").is_err());
        assert_eq!(parse_hex("0aff").unwrap(), vec![0x0a, 0xff]);
    }

    /// A server resolves names with the machine's own resolver, which strict
    /// mode refuses; the Zray-only `leakPolicy` key is how a server asks.
    #[test]
    fn the_dns_leak_policy_is_strict_unless_a_server_says_otherwise() {
        let policy = |dns: serde_json::Value| {
            let (config, _) = parse_config(&serde_json::json!({
                "inbounds": [], "outbounds": [{"protocol": "freedom"}], "dns": dns
            }))
            .unwrap();
            config.dns.leak_policy
        };
        // A config that sends traffic through a proxy is a client, and cannot
        // ask for the machine's resolver.
        let (client, _) = parse_config(&serde_json::json!({
            "inbounds": [],
            "outbounds": [{"protocol": "freedom"}, {"protocol": "socks", "settings": {"address": "127.0.0.1", "port": 9050}}],
            "dns": {"servers": ["localhost"], "leakPolicy": "fallback"}
        }))
        .unwrap();
        assert_eq!(client.dns.leak_policy, LeakPolicy::Strict);
        assert_eq!(
            policy(serde_json::json!({"servers": ["localhost"]})),
            LeakPolicy::Strict
        );
        assert_eq!(
            policy(serde_json::json!({"servers": ["localhost"], "leakPolicy": "fallback"})),
            LeakPolicy::Fallback
        );
        assert_eq!(
            policy(serde_json::json!({"servers": ["localhost"], "leakPolicy": "nonsense"})),
            LeakPolicy::Strict
        );
    }

    #[test]
    fn juicity_outbound_reads_uuid_password_and_server() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "juicity",
                "settings": {
                    "address": "proxy.example",
                    "port": 20000,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "password": "correct-horse"
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {"serverName": "proxy.example", "alpn": ["h3"]}
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let OutboundProtocol::Juicity(juicity) = &config.outbounds[0].protocol else {
            panic!("expected juicity, got {:?}", config.outbounds[0].protocol);
        };
        assert_eq!(juicity.port, 20000);
        assert_eq!(&*juicity.password, "correct-horse");
        assert_eq!(juicity.uuid[15], 1);
    }

    #[test]
    fn shadowtls_outbound_reads_password_sni_and_alpn() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": "relay.example",
                        "port": 443,
                        "method": "2022-blake3-aes-128-gcm",
                        "password": "inner-ss-key"
                    }]
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {
                        "version": 3,
                        "password": "stls-secret",
                        "tls": {"serverName": "www.microsoft.com", "alpn": ["h2"]}
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let outbound = &config.outbounds[0];
        assert!(matches!(
            &outbound.protocol,
            OutboundProtocol::Shadowsocks(_)
        ));
        let Security::ShadowTls(stls) = &outbound.stream.security else {
            panic!("expected shadowtls, got {:?}", outbound.stream.security);
        };
        assert_eq!(&*stls.password, "stls-secret");
        assert_eq!(&*stls.server_name, "www.microsoft.com");
        assert_eq!(stls.alpn.len(), 1);
        assert_eq!(&*stls.alpn[0], "h2");
    }

    #[test]
    fn shadowtls_defaults_alpn_when_omitted() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": "relay.example",
                        "port": 443,
                        "method": "aes-256-gcm",
                        "password": "inner-ss-key"
                    }]
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {
                        "password": "stls-secret",
                        "tls": {"serverName": "www.microsoft.com"}
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let Security::ShadowTls(stls) = &config.outbounds[0].stream.security else {
            panic!("expected shadowtls");
        };
        assert_eq!(
            stls.alpn.iter().map(|a| &**a).collect::<Vec<_>>(),
            vec!["h2", "http/1.1"]
        );
    }

    #[test]
    fn shadowtls_rejects_non_v3_and_missing_fields() {
        let v2 = serde_json::json!({
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "relay.example", "port": 443,
                    "method": "aes-256-gcm", "password": "k"
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {
                        "version": 2,
                        "password": "stls-secret",
                        "tls": {"serverName": "www.microsoft.com"}
                    }
                }
            }]
        });
        assert!(parse_config(&v2).is_err(), "v2 must be rejected");

        let no_sni = serde_json::json!({
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "relay.example", "port": 443,
                    "method": "aes-256-gcm", "password": "k"
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {"password": "stls-secret", "tls": {}}
                }
            }]
        });
        assert!(
            parse_config(&no_sni).is_err(),
            "missing serverName rejected"
        );
    }

    #[test]
    fn shadowtls_requires_a_shadowsocks_inner() {
        // ShadowTLS over a non-Shadowsocks protocol must fail the model's
        // validation: the client only knows how to carry Shadowsocks inside.
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "trojan",
                "settings": {"servers": [{
                    "address": "relay.example", "port": 443, "password": "k"
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "shadowtls",
                    "shadowtlsSettings": {
                        "password": "stls-secret",
                        "tls": {"serverName": "www.microsoft.com"}
                    }
                }
            }]
        });
        assert!(
            parse_config(&value).is_err(),
            "shadowtls must reject a non-shadowsocks inner protocol"
        );
    }

    #[test]
    fn ports_are_range_checked_instead_of_truncated() {
        assert_eq!(json_port(&serde_json::json!(443)), Some(443));
        assert_eq!(json_port(&serde_json::json!("8443")), Some(8443));
        assert_eq!(json_port(&serde_json::json!(70_000)), None);
        assert_eq!(json_port(&serde_json::json!(0)), None);
        assert_eq!(json_port(&serde_json::json!(-5)), None);
        assert_eq!(json_port(&serde_json::json!("http")), None);
        // A routing port past 65535 must not wrap onto a real port (70000
        // used to become 4464).
        assert!(parse_port_list(&serde_json::json!(70_000)).is_empty());
        assert_eq!(parse_port_list(&serde_json::json!(443)).len(), 1);
    }

    #[test]
    fn freedom_target_strategy_reaches_the_direct_dial_policy() {
        let value = serde_json::json!({
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"targetStrategy": "UseIPv4"},
                "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}
            }]
        });
        let (config, _) = parse_config(&value).expect("valid matching strategies");
        let outbound = &config.outbounds[0];
        assert!(matches!(
            outbound.protocol,
            OutboundProtocol::Freedom {
                domain_strategy: DomainStrategy::UseIpv4
            }
        ));
        assert_eq!(
            outbound.stream.sockopt.domain_strategy,
            DomainStrategy::UseIpv4
        );
    }

    #[test]
    fn freedom_domain_strategy_rejects_unknown_or_conflicting_values() {
        let unknown = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "settings": {"targetStrategy": "ForceIPv4"}
            }]
        });
        assert!(parse_config(&unknown)
            .unwrap_err()
            .contains("unsupported domain strategy"));

        let conflict = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "settings": {
                    "targetStrategy": "UseIPv4",
                    "domainStrategy": "UseIPv6"
                }
            }]
        });
        assert!(parse_config(&conflict)
            .unwrap_err()
            .contains("conflicts with deprecated domainStrategy"));

        let sockopt = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv6"}}
            }]
        });
        assert!(parse_config(&sockopt)
            .unwrap_err()
            .contains("sockopt.domainStrategy has unsupported"));
    }

    #[test]
    fn tcp_congestion_parses_and_a_blank_name_means_system_default() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "streamSettings": {"sockopt": {"tcpCongestion": "bbr"}}
            }]
        });
        let (config, _) = parse_config(&value).expect("a named algorithm is not config");
        assert_eq!(
            config.outbounds[0].stream.sockopt.tcp_congestion.as_deref(),
            Some("bbr")
        );

        // A blank or whitespace name is dropped, not passed through: setting
        // a sockopt called "" is never what the author meant.
        let blank = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "streamSettings": {"sockopt": {"tcpCongestion": "  "}}
            }]
        });
        let (config, _) = parse_config(&blank).expect("blank is still valid config");
        assert!(config.outbounds[0].stream.sockopt.tcp_congestion.is_none());
    }

    #[test]
    fn tcp_congestion_layers_onto_a_link_outbound() {
        // The dominant stored shape is the share link, which can only
        // describe a server — the congestion control is a property of this
        // machine's dial, so it arrives as an overlay.
        let link = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
                    ?security=reality&sni=www.googletagmanager.com&fp=chrome\
                    &pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef\
                    &type=tcp&encryption=none#Example";
        let value = serde_json::json!({
            "outbounds": [{
                "link": link,
                "streamSettings": {"sockopt": {"tcpCongestion": "bbr"}}
            }]
        });
        let (config, _) = parse_config(&value).expect("overlay must parse");
        assert_eq!(
            config.outbounds[0].stream.sockopt.tcp_congestion.as_deref(),
            Some("bbr")
        );

        // A link without the overlay keeps the system default.
        let bare = serde_json::json!({"outbounds": [{"link": link}]});
        let (config, _) = parse_config(&bare).expect("bare link must parse");
        assert!(config.outbounds[0].stream.sockopt.tcp_congestion.is_none());
    }

    #[test]
    fn inbound_xhttp_h3_is_compiled_as_stream_one() {
        let value = serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/service",
                "mode": "stream-one",
                "httpVersion": "3"
            }
        });
        let transport = parse_inbound_transport(&value, "inbounds[0]").unwrap();
        let Transport::Xhttp(settings) = transport else {
            panic!("expected XHTTP transport")
        };
        assert_eq!(settings.xhttp_http_version, XhttpHttpVersion::Http3);
        assert_eq!(settings.xhttp_mode, XhttpMode::StreamOne);
    }

    #[test]
    fn inbound_xhttp_h3_packet_mode_is_compiled() {
        let value = serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/service",
                "mode": "packet-up",
                "httpVersion": "3"
            }
        });
        let transport = parse_inbound_transport(&value, "inbounds[0]").unwrap();
        let Transport::Xhttp(settings) = transport else {
            panic!("expected XHTTP transport")
        };
        assert_eq!(settings.xhttp_http_version, XhttpHttpVersion::Http3);
        assert_eq!(settings.xhttp_mode, XhttpMode::PacketUp);
    }

    #[test]
    fn inbound_xhttp_h3_stream_up_is_compiled() {
        let value = serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/service",
                "mode": "stream-up",
                "httpVersion": "3"
            }
        });
        let transport = parse_inbound_transport(&value, "inbounds[0]").unwrap();
        let Transport::Xhttp(settings) = transport else {
            panic!("expected XHTTP transport")
        };
        assert_eq!(settings.xhttp_mode, XhttpMode::StreamUp);
    }

    /// Xray's `lengths` list: leading zeros are empty records, the last
    /// entry sizes the pieces.
    #[test]
    fn a_fragment_mask_can_ask_for_empty_records_before_the_hello() {
        let mask = |settings: Value| parse_fragment(Some(&settings), "o");
        let parsed = mask(serde_json::json!({
            "packets": "tlshello", "lengths": ["0", "100-200"], "delays": ["0"]
        }))
        .unwrap();
        assert_eq!(parsed.empty_records, 1);
        assert_eq!(parsed.length, RangeU32::new(100, 200));
        assert_eq!(parsed.delay, RangeDuration::millis(0, 0));
        // The plain single range still works and asks for none.
        let plain = mask(serde_json::json!({"packets": "tlshello", "length": "50"})).unwrap();
        assert_eq!((plain.empty_records, plain.length.min), (0, 50));
        // The last entry has to move bytes, and an empty record needs TLS framing.
        assert!(mask(serde_json::json!({"packets": "tlshello", "lengths": ["0"]})).is_err());
        assert!(mask(serde_json::json!({"packets": "1-1", "lengths": ["0", "40"]})).is_err());
        assert!(mask(serde_json::json!({"packets": "tlshello", "lengths": "0"})).is_err());
    }

    #[test]
    fn legacy_freedom_fragment_and_noise_are_compiled() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "settings": {
                    "fragment": {
                        "packets": "tlshello",
                        "length": "120-160",
                        "interval": "2-4",
                        "maxSplit": "5"
                    },
                    "noises": [{
                        "type": "rand",
                        "packet": "8-12",
                        "delay": "1-2",
                        "count": 3
                    }]
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        assert!(config.outbounds[0].stream.evasion.tcp_fragment.is_some());
        assert_eq!(config.outbounds[0].stream.evasion.udp_noise.len(), 1);
        assert_eq!(
            config.outbounds[0]
                .stream
                .evasion
                .tcp_fragment
                .as_ref()
                .unwrap()
                .max_split
                .max,
            5
        );
    }

    #[test]
    fn amnezia_wireguard_outbound_is_compiled_with_obfuscation() {
        use base64::Engine;

        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "amnezia-wg",
                "tag": "warp",
                "settings": {
                    "privateKey": key,
                    "peerPublicKey": key,
                    "presharedKey": key,
                    "endpoint": "198.51.100.10:51820",
                    "tunnelAddress": "10.0.0.2/32",
                    "persistentKeepalive": 25,
                    "amnezia": {
                        "jc": 5,
                        "jmin": 50,
                        "jmax": 100,
                        "s1": 0,
                        "s2": 0,
                        "h1": "1-10",
                        "h2": 20,
                        "h3": 30,
                        "h4": 40
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let OutboundProtocol::AmneziaWireguard(wireguard) = &config.outbounds[0].protocol else {
            panic!("expected AmneziaWG outbound")
        };
        assert_eq!(wireguard.port, 51820);
        assert!(wireguard.preshared_key.is_some());
        assert_eq!(wireguard.junk_count, 5);
        assert_eq!(wireguard.junk_min, 50);
        assert_eq!(wireguard.junk_max, 100);
        assert_eq!(wireguard.h1.min, 1);
        assert_eq!(wireguard.h1.max, 10);
        assert_eq!(wireguard.h4.min, 40);
        assert_eq!(wireguard.h4.max, 40);
    }

    fn warp_account() -> serde_json::Value {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let der = base64::engine::general_purpose::STANDARD.encode([1u8; 40]);
        serde_json::json!({
            "route": "auto",
            "wireguard": {
                "privateKey": key,
                "peerPublicKey": key,
                "endpoint": "162.159.192.1:2408",
                "reserved": [1, 2, 3],
                "amnezia": {"jc": 4, "jmin": 40, "jmax": 70}
            },
            "masque": {
                "privateKey": der,
                "serverPublicKey": format!("-----BEGIN PUBLIC KEY-----\n{der}\n-----END PUBLIC KEY-----"),
                "address": ["172.16.0.2/32", "2606:4700:110:8a36::1"]
            }
        })
    }

    fn warp_outbound(settings: serde_json::Value) -> Result<AmneziaWireguardConfig, String> {
        let value = serde_json::json!({
            "outbounds": [{"protocol": "warp", "tag": "warp", "settings": settings}]
        });
        let (config, _) = parse_config(&value)?;
        match &config.outbounds[0].protocol {
            OutboundProtocol::AmneziaWireguard(wireguard) => Ok(wireguard.clone()),
            other => Err(format!("unexpected {other:?}")),
        }
    }

    #[test]
    fn a_warp_account_carries_both_halves_and_defaults_to_auto() {
        let warp = warp_outbound(warp_account()).unwrap();
        assert_eq!(warp.route, WarpRoute::Auto);
        assert!(warp.wireguard_usable());
        assert_eq!(warp.reserved, [1, 2, 3]);
        assert_eq!(warp.junk_count, 4);
        // The WireGuard half took its tunnel address from the MASQUE half.
        assert_eq!(warp.tunnel_address.to_string(), "172.16.0.2");
        let masque = warp.masque.unwrap();
        assert_eq!(masque.addresses.len(), 2);
        assert_eq!(masque.server_public_key, vec![1u8; 40]);
        assert_eq!(masque.http2_sni.as_ref(), MasqueConfig::DEFAULT_HTTP2_SNI);
        assert_eq!(masque.http2_endpoints[0].to_string(), "162.159.198.4:443");
        assert_eq!(masque.http3_endpoints[0].to_string(), "162.159.198.1:443");
        // The key stays out of the debug output.
        assert!(!format!("{masque:?}").contains("private_key"));
    }

    #[test]
    fn a_masque_only_account_needs_no_wireguard_keys() {
        let mut settings = warp_account();
        settings.as_object_mut().unwrap().remove("wireguard");
        settings["route"] = "masque-h2".into();
        settings["masque"]["http2Endpoints"] =
            serde_json::json!(["203.0.113.9", "[2001:db8::9]:8443"]);
        let warp = warp_outbound(settings).unwrap();
        assert!(!warp.wireguard_usable());
        assert_eq!(warp.route, WarpRoute::MasqueHttp2);
        let endpoints = warp.masque.unwrap().http2_endpoints;
        assert_eq!(endpoints[0].to_string(), "203.0.113.9:443");
        assert_eq!(endpoints[1].to_string(), "[2001:db8::9]:8443");
    }

    #[test]
    fn a_warp_outbound_without_a_usable_route_is_refused() {
        // Nothing at all.
        assert!(warp_outbound(serde_json::json!({})).is_err());
        // Pinned to a transport whose half is missing.
        let mut settings = warp_account();
        settings.as_object_mut().unwrap().remove("masque");
        settings["wireguard"]["address"] = "172.16.0.2".into();
        settings["route"] = "masque-h3".into();
        let error = warp_outbound(settings).unwrap_err();
        assert!(error.contains("MASQUE key"), "{error}");
        let mut settings = warp_account();
        settings.as_object_mut().unwrap().remove("wireguard");
        settings["route"] = "wireguard".into();
        assert!(warp_outbound(settings).unwrap_err().contains("WireGuard"));
        // An unknown route name, a bad key, and a missing address.
        let mut settings = warp_account();
        settings["route"] = "carrier-pigeon".into();
        assert!(warp_outbound(settings).is_err());
        let mut settings = warp_account();
        settings["masque"]["privateKey"] = "!!!".into();
        assert!(warp_outbound(settings).is_err());
        let mut settings = warp_account();
        settings["masque"]["address"] = serde_json::json!([]);
        assert!(warp_outbound(settings).is_err());
    }

    #[test]
    fn a_warp_outbound_can_name_exits_and_which_order_they_go_in() {
        let mut settings = warp_account();
        settings["exits"] = serde_json::json!([
            "trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#one",
            "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443?security=tls&sni=v.example.com#two"
        ]);
        let warp = warp_outbound(settings.clone()).unwrap();
        assert_eq!(warp.exits.len(), 2);
        assert_eq!(
            (warp.hybrid, warp.prefer_exit),
            (HybridMode::WarpFirst, false)
        );
        settings["mode"] = "server-first".into();
        let warp = warp_outbound(settings.clone()).unwrap();
        assert_eq!(
            (warp.hybrid, warp.prefer_exit),
            (HybridMode::ServerFirst, false)
        );
        // preferExit only means something inside the tunnel-first order.
        settings["preferExit"] = true.into();
        assert!(!warp_outbound(settings.clone()).unwrap().prefer_exit);
        settings["mode"] = "warp-first".into();
        let warp = warp_outbound(settings.clone()).unwrap();
        assert_eq!(
            (warp.hybrid, warp.prefer_exit),
            (HybridMode::WarpFirst, true)
        );
        // What older builds wrote keeps its meaning.
        settings.as_object_mut().unwrap().remove("preferExit");
        settings["mode"] = "hybrid".into();
        let warp = warp_outbound(settings.clone()).unwrap();
        assert_eq!(
            (warp.hybrid, warp.prefer_exit),
            (HybridMode::WarpFirst, false)
        );
        settings["mode"] = "reverse".into();
        let warp = warp_outbound(settings.clone()).unwrap();
        assert_eq!(
            (warp.hybrid, warp.prefer_exit),
            (HybridMode::WarpFirst, true)
        );
        // An exit that cannot follow a tunnel (QUIC needs its own socket).
        let mut quic = settings.clone();
        quic["exits"] = serde_json::json!(["hy2://pw@203.0.113.9:443?sni=h.example.com#q"]);
        assert!(warp_outbound(quic).unwrap_err().contains("cannot follow"));
        // Nonsense, and preferring an exit with none to prefer.
        let mut bad = settings.clone();
        bad["exits"] = serde_json::json!(["not a link"]);
        assert!(warp_outbound(bad).is_err());
        let mut none = warp_account();
        none["mode"] = "reverse".into();
        assert!(warp_outbound(none)
            .unwrap_err()
            .contains("at least one exit"));
        let mut unknown = warp_account();
        unknown["mode"] = "sideways".into();
        assert!(warp_outbound(unknown).is_err());
        // The order is kept with no servers listed yet, so a search later
        // looks for the right kind.
        let mut empty = warp_account();
        empty["mode"] = "server-first".into();
        assert_eq!(
            warp_outbound(empty).unwrap().hybrid,
            HybridMode::ServerFirst
        );
    }

    #[test]
    fn a_link_outbound_can_be_carried_by_another_outbound() {
        let value = serde_json::json!({"outbounds": [
            {"tag": "server", "link": "trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#s",
             "streamSettings": {"sockopt": {"dialerProxy": "warp"}}},
            {"tag": "warp", "protocol": "freedom"}
        ]});
        let (config, _) = parse_config(&value).unwrap();
        assert_eq!(
            config.outbounds[0].stream.sockopt.dialer_proxy.as_deref(),
            Some("warp")
        );
        assert!(config.outbounds[1].stream.sockopt.dialer_proxy.is_none());
    }

    #[test]
    fn a_zerov1_link_can_be_carried_by_another_outbound() {
        let value = serde_json::json!({"outbounds": [
            {"tag": "tide", "link": "zerov1://IJs62pjNyTJ6lcQI2RTJgw@203.0.113.9:443?key=8IlzK3FhAVnYNxXhX2Xvo8xANX6TjE8-zdHPObMR02A&path=%2Fstatic%2Fabc&security=tls&sni=t.example.com#t",
             "streamSettings": {"sockopt": {"dialerProxy": "reality"}}},
            {"tag": "reality", "link": "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&fp=chrome&type=tcp#r"}
        ]});
        let (config, _) = parse_config(&value).unwrap();
        assert!(matches!(
            config.outbounds[0].protocol,
            crate::model::OutboundProtocol::Tide(_)
        ));
        assert_eq!(
            config.outbounds[0].stream.sockopt.dialer_proxy.as_deref(),
            Some("reality")
        );
    }

    #[test]
    fn xray_wireguard_peer_shape_is_compiled() {
        use base64::Engine;

        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "wireguard",
                "settings": {
                    "secretKey": key,
                    "address": ["172.16.0.2/32", "2606:4700:110:8765::2/128"],
                    "peers": [{
                        "publicKey": key,
                        "endpoint": "162.159.192.1:2408",
                        "keepAlive": 25
                    }]
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let OutboundProtocol::AmneziaWireguard(wireguard) = &config.outbounds[0].protocol else {
            panic!("expected WireGuard outbound")
        };
        assert_eq!(wireguard.address, Address::parse_host("162.159.192.1"));
        assert_eq!(wireguard.port, 2408);
        assert_eq!(
            wireguard.tunnel_address,
            "172.16.0.2".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(wireguard.persistent_keepalive, Some(25));
    }

    #[test]
    fn malformed_amnezia_numeric_settings_fail_closed() {
        use base64::Engine;

        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "amnezia-wg",
                "settings": {
                    "privateKey": key,
                    "peerPublicKey": key,
                    "endpoint": "198.51.100.10:51820",
                    "tunnelAddress": "10.0.0.2/32",
                    "amnezia": {"jc": "not-a-number"}
                }
            }]
        });
        let error = parse_config(&value).unwrap_err();
        assert!(error.contains("settings.jc"));
        assert!(error.contains("value is invalid"));
    }

    /// The pairing in use in Iran: an empty record, a 104-byte record and
    /// single bytes in one write, with a TCP split underneath. The later
    /// entry of `finalmask.tcp` is the one on top, as in Xray.
    #[test]
    fn listed_lengths_and_two_stacked_fragment_masks_are_kept_as_written() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "streamSettings": {
                    "finalmask": {
                        "tcp": [
                            {"type": "fragment", "settings": {
                                "packets": "1-1", "lengths": ["114", "1"],
                                "delays": ["1"], "maxSplit": "11"
                            }},
                            {"type": "fragment", "settings": {
                                "packets": "tlshello", "lengths": ["0", "104", "1"],
                                "delays": ["0"], "maxSplit": "11"
                            }}
                        ]
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let evasion = &config.outbounds[0].stream.evasion;
        let top = evasion.tcp_fragment.as_ref().expect("the later mask");
        assert_eq!(top.packets, FragmentPackets::TlsHello);
        assert_eq!(top.empty_records, 1);
        assert_eq!(top.lead_lengths, [RangeU32::new(104, 104)]);
        assert_eq!(top.length, RangeU32::new(1, 1));
        assert!(top.lead_delays.is_empty());
        assert_eq!(top.delay, RangeDuration::millis(0, 0));
        let under = evasion
            .tcp_fragment_under
            .as_ref()
            .expect("the earlier mask");
        assert_eq!(under.packets, FragmentPackets::Range { from: 1, to: 1 });
        assert_eq!(under.lead_lengths, [RangeU32::new(114, 114)]);
        assert_eq!(under.max_split, RangeU32::new(11, 11));

        // A third mask has nowhere to go, and a zero cannot cut raw bytes.
        let mut three = value.clone();
        let masks = three["outbounds"][0]["streamSettings"]["finalmask"]["tcp"]
            .as_array_mut()
            .unwrap();
        masks.push(masks[0].clone());
        assert!(parse_config(&three).unwrap_err().contains("at most two"));
        let mut zero = value;
        zero["outbounds"][0]["streamSettings"]["finalmask"]["tcp"][0]["settings"]["lengths"] =
            serde_json::json!(["5", "0", "9"]);
        assert!(parse_config(&zero).unwrap_err().contains("tlshello"));
    }

    #[test]
    fn legacy_and_finalmask_evasion_cannot_be_ambiguous() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "freedom",
                "settings": {
                    "fragment": {"length": "100-100"}
                },
                "streamSettings": {
                    "finalmask": {
                        "tcp": [{
                            "type": "fragment",
                            "settings": {"length": "100-100"}
                        }]
                    }
                }
            }]
        });
        let error = parse_config(&value).unwrap_err();
        assert!(error.contains("either settings.fragment/noises"));
    }

    #[test]
    fn raw_http_header_is_compiled_for_client_and_inbound_shapes() {
        let value = serde_json::json!({
            "network": "tcp",
            "tcpSettings": {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": ["/cdn-cgi/trace"],
                        "headers": {"Host": ["example.test"]}
                    },
                    "response": {
                        "version": "1.1",
                        "status": "204",
                        "reason": "No Content"
                    }
                }
            }
        });
        let stream = parse_stream(&value, "outbounds[0]", &mut ParseOutput::default()).unwrap();
        let header = stream.raw_http_header.unwrap();
        assert_eq!(header.request.path.as_ref(), "/cdn-cgi/trace");
        assert_eq!(header.request.headers["Host"].as_ref(), "example.test");
        assert_eq!(header.response.unwrap().status, 204);
    }

    #[test]
    fn ech_config_is_decoded_and_retains_inner_name() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "proxy.example",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "proxy.example",
                        "enableECH": true,
                        "echServerName": "public.example",
                        "echConfigList": "AGH+DQBdAAAgACAkIyMKSFWhOMEcF6lVctzNZE71S5DqKdc3bPtN7JpZCAAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAA5wdWJsaWMuZXhhbXBsZQAA"
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let Security::Tls(tls) = &config.outbounds[0].stream.security else {
            panic!("expected ordinary TLS");
        };
        let ech = tls.ech.as_ref().expect("ECH settings");
        assert_eq!(ech.server_name.as_deref(), Some("public.example"));
        assert_eq!(ech.config_list.len(), 99);
    }

    #[test]
    fn ech_without_a_list_is_marked_for_resolver_discovery() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "proxy.example",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "proxy.example",
                        "enableECH": true
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let Security::Tls(tls) = &config.outbounds[0].stream.security else {
            panic!("expected certificate TLS")
        };
        let ech = tls.ech.as_ref().expect("ECH marker");
        assert!(ech.config_list.is_empty());

        // Xray's "look it up" spelling asks for the same thing.
        let mut queried = value.clone();
        queried["outbounds"][0]["streamSettings"]["tlsSettings"] = serde_json::json!({
            "serverName": "proxy.example",
            "echConfigList": "cloudflare-ech.com+udp://1.1.1.1"
        });
        let (config, _) = parse_config(&queried).unwrap();
        let Security::Tls(tls) = &config.outbounds[0].stream.security else {
            panic!("expected certificate TLS")
        };
        let ech = tls.ech.as_ref().expect("ECH marker");
        assert!(ech.config_list.is_empty());
        // The name before the `+` is where the list is looked up.
        assert_eq!(ech.query_name.as_deref(), Some("cloudflare-ech.com"));

        // A query with no name leaves the lookup to the server name.
        queried["outbounds"][0]["streamSettings"]["tlsSettings"]["echConfigList"] =
            serde_json::json!("udp://8.8.8.8");
        let (config, _) = parse_config(&queried).unwrap();
        let Security::Tls(tls) = &config.outbounds[0].stream.security else {
            panic!("expected certificate TLS")
        };
        assert_eq!(tls.ech.as_ref().expect("ECH marker").query_name, None);
    }

    #[test]
    fn a_link_outbound_takes_stacked_fragment_masks_in_finalmask_form() {
        let link = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
            ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&encryption=none";
        let mask = serde_json::json!({"tcp": [
            {"type": "fragment", "settings": {"packets": "tlshello",
                "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},
            {"type": "fragment", "settings": {"packets": "1-1",
                "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}},
        ]});
        let value = serde_json::json!({"outbounds": [{"link": link, "finalmask": mask}]});
        let (config, _) = parse_config(&value).unwrap();
        let evasion = &config.outbounds[0].stream.evasion;
        // The later entry sits on top and cuts first; the earlier one is under.
        assert_eq!(
            evasion.tcp_fragment.as_ref().unwrap().packets,
            FragmentPackets::Range { from: 1, to: 1 }
        );
        assert_eq!(
            evasion.tcp_fragment_under.as_ref().unwrap().packets,
            FragmentPackets::TlsHello
        );
        // Without it the link has no evasion.
        let value = serde_json::json!({"outbounds": [{"link": link}]});
        let (config, _) = parse_config(&value).unwrap();
        assert!(config.outbounds[0].stream.evasion.is_empty());
    }

    #[test]
    fn panel_configs_that_write_empty_strings_for_nothing_load() {
        // `"security": ""`, `"preSharedKey": ""` and `"outboundTag": ""` next
        // to a `balancerTag` are how BPB's WoW and WorkerLess configs say
        // "none".
        let value = serde_json::json!({
            "outbounds": [
                {"tag": "a", "protocol": "freedom", "settings": {},
                 "streamSettings": {"network": "tcp", "security": ""}},
                {"tag": "b", "protocol": "freedom", "settings": {}}
            ],
            "routing": {
                "balancers": [{"tag": "all", "selector": ["a", "b"],
                               "strategy": {"type": "leastPing"}}],
                "rules": [{"type": "field", "network": "tcp,udp",
                           "balancerTag": "all", "outboundTag": ""}]
            }
        });
        let (config, _) = parse_config(&value).unwrap();
        assert!(matches!(
            config.outbounds[0].stream.security,
            Security::None
        ));
        assert!(matches!(
            config.routing.rules[0].target,
            crate::routing::RuleTarget::Balancer(_)
        ));
    }

    #[test]
    fn an_empty_ws_host_means_the_server_name_not_an_empty_header() {
        // BPB writes `"Host": ""` in its fragment configs.
        let value = serde_json::json!({"outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "188.114.96.3", "port": 443,
                "users": [{"id": "00000000-0000-0000-0000-000000000002"}]}]},
            "streamSettings": {"network": "ws", "security": "tls",
                "tlsSettings": {"serverName": "MySub.Example.WORKERS.dev"},
                "wsSettings": {"headers": {"Host": ""}, "path": "/p?ed=2560"}}
        }]});
        let (config, _) = parse_config(&value).unwrap();
        let Transport::WebSocket(ws) = &config.outbounds[0].stream.transport else {
            panic!("expected WebSocket");
        };
        assert_eq!(ws.host.as_deref(), Some("MySub.Example.WORKERS.dev"));
        assert!(ws.headers.is_empty());
    }

    #[test]
    fn hysteria2_settings_take_a_salamander_obfs() {
        let outbound = |obfs: serde_json::Value| {
            serde_json::json!({"outbounds": [{
                "protocol": "hysteria2",
                "settings": {"address": "203.0.113.9", "port": 8443,
                             "password": "secret", "obfs": obfs},
                "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "a.example"}}
            }]})
        };
        let (config, _) = parse_config(&outbound(
            serde_json::json!({"type": "salamander", "password": "gawrgura"}),
        ))
        .unwrap();
        let OutboundProtocol::Hysteria2(hysteria) = &config.outbounds[0].protocol else {
            panic!("expected Hysteria2");
        };
        assert_eq!(hysteria.obfs_password.as_deref(), Some("gawrgura"));
        // Another type, or a password the server would not take, is refused.
        let error = |obfs| parse_config(&outbound(obfs)).unwrap_err();
        assert!(
            error(serde_json::json!({"type": "gecko", "password": "gawrgura"}))
                .contains("only salamander")
        );
        assert!(
            error(serde_json::json!({"type": "salamander", "password": "abc"})).contains("4 bytes")
        );
        let (config, _) = parse_config(&outbound(serde_json::Value::Null)).unwrap();
        let OutboundProtocol::Hysteria2(hysteria) = &config.outbounds[0].protocol else {
            panic!("expected Hysteria2");
        };
        assert_eq!(hysteria.obfs_password, None);
    }

    #[test]
    fn a_link_outbound_can_be_told_to_skip_certificate_checks_for_every_link() {
        let tls = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
            ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&encryption=none";
        let asked = format!("{tls}&allowInsecure=1");
        let reality = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
            ?security=reality&sni=www.example.com&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\
            &fp=chrome&sid=ab&type=tcp&encryption=none";
        let insecure_of = |entry: serde_json::Value| {
            let value = serde_json::json!({"outbounds": [entry]});
            let (config, _) = parse_config(&value).unwrap();
            match &config.outbounds[0].stream.security {
                Security::Tls(tls) => Some(tls.allow_insecure),
                _ => None,
            }
        };
        // Off by default, on only when asked.
        assert_eq!(insecure_of(serde_json::json!({"link": tls})), Some(false));
        assert_eq!(
            insecure_of(serde_json::json!({"link": tls, "allowInsecure": true})),
            Some(true)
        );
        // `false` or absent never takes away what the link itself asked for.
        assert_eq!(insecure_of(serde_json::json!({"link": asked})), Some(true));
        assert_eq!(
            insecure_of(serde_json::json!({"link": asked, "allowInsecure": false})),
            Some(true)
        );
        // A carrier with no certificate to skip is left alone, not refused.
        assert_eq!(
            insecure_of(serde_json::json!({"link": reality, "allowInsecure": true})),
            None
        );
    }

    #[test]
    fn a_link_outbound_can_be_given_or_stripped_of_ech() {
        let link = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
            ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&encryption=none";
        let ech_of = |entry: serde_json::Value| {
            let value = serde_json::json!({"outbounds": [entry]});
            let (config, _) = parse_config(&value).unwrap();
            let Security::Tls(tls) = &config.outbounds[0].stream.security else {
                panic!("expected certificate TLS")
            };
            tls.ech.is_some()
        };
        assert!(!ech_of(serde_json::json!({"link": link})));
        assert!(ech_of(serde_json::json!({"link": link, "ech": true})));
        let asked = format!("{link}&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1");
        assert!(ech_of(serde_json::json!({"link": asked})));
        assert!(!ech_of(serde_json::json!({"link": asked, "ech": false})));
        // It needs a TLS name to hide: REALITY has none to encrypt.
        let reality = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
            ?security=reality&sni=www.example.com&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\
            &sid=0123456789abcdef&type=tcp&encryption=none";
        let value = serde_json::json!({"outbounds": [{"link": reality, "ech": true}]});
        assert!(parse_config(&value).unwrap_err().contains("ech needs"));
    }

    #[test]
    fn a_link_outbound_can_be_moved_to_another_port() {
        let link = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
            ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&encryption=none";
        let port_of = |entry: serde_json::Value| {
            let value = serde_json::json!({"outbounds": [entry]});
            parse_config(&value).map(|(config, _)| config.outbounds[0].endpoint().unwrap().1)
        };
        assert_eq!(port_of(serde_json::json!({"link": link})), Ok(443));
        assert_eq!(
            port_of(serde_json::json!({"link": link, "port": 2053})),
            Ok(2053)
        );
        assert!(port_of(serde_json::json!({"link": link, "port": 0})).is_err());
        assert!(port_of(serde_json::json!({"link": link, "port": 70000})).is_err());
    }

    #[test]
    fn reality_mldsa65_verify_key_is_decoded_and_bounded() {
        use base64::Engine;

        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a; 1952]);
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.test",
                        "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "fingerprint": "chrome",
                        "mldsa65Verify": key
                    }
                }
            }]
        });
        let (config, _) = parse_config(&value).unwrap();
        let Security::Reality(reality) = &config.outbounds[0].stream.security else {
            panic!("expected REALITY")
        };
        assert_eq!(reality.mldsa65_verify.as_deref(), Some(&[0x5a; 1952][..]));
    }

    #[test]
    fn legacy_vmess_alter_id_is_rejected_with_an_actionable_message() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "proxy.example",
                    "port": 443,
                    "users": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "alterId": 64
                    }]
                }]},
                "streamSettings": {"network": "raw", "security": "none"}
            }]
        });
        let error = parse_config(&value).expect_err("nonzero alterId must be rejected");
        assert!(
            error.contains("alterId") && error.contains("AEAD"),
            "error should explain the alterId requirement: {error}"
        );
    }

    #[test]
    fn zero_vmess_alter_id_is_accepted() {
        let value = serde_json::json!({
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "proxy.example",
                    "port": 443,
                    "users": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "alterId": 0
                    }]
                }]},
                "streamSettings": {"network": "raw", "security": "none"}
            }]
        });
        assert!(parse_config(&value).is_ok(), "alterId 0 is the AEAD case");
    }
    #[test]
    fn the_record_method_needs_no_decoy_name() {
        let parsed = parse_sni_spoof(&serde_json::json!({"method": "record"}), "x").unwrap();
        assert_eq!(parsed.method, crate::model::SniMethod::Record);
        let alias = parse_sni_spoof(&serde_json::json!({"method": "recordversion"}), "x").unwrap();
        assert_eq!(alias.method, crate::model::SniMethod::Record);
        let empty = parse_sni_spoof(&serde_json::json!({"method": "empty"}), "x").unwrap();
        assert_eq!(empty.method, crate::model::SniMethod::EmptyRecord);
        assert!(parse_sni_spoof(&serde_json::json!({"method": "sudoku"}), "x").is_err());
    }

    #[test]
    fn quic_rates_are_counted_the_way_xray_counts_them() {
        let rate = |text: &str| parse_rate(&Value::from(text), "r").unwrap();
        assert_eq!(rate("20 mbps"), 2_621_440);
        assert_eq!(rate("20mb"), 2_621_440);
        assert_eq!(rate("1g"), 134_217_728);
        assert_eq!(rate("0"), 0);
        assert!(
            parse_rate(&Value::from("100"), "r").is_err(),
            "below 65535 bps"
        );
        assert!(parse_rate(&Value::from("5 parsecs"), "r").is_err());
        assert_eq!(parse_rate(&Value::from(0), "r").unwrap(), 0);
    }

    #[test]
    fn finalmask_udp_masks_become_quic_shaping() {
        let mask = serde_json::json!({
            "udp": [
                {"type": "salamander", "settings": {"password": "obfs-secret"}},
                {"type": "udphop", "settings": {
                    "mode": "intervallocal", "interval": "5-10", "remotePorts": "20000-20002,443"
                }},
            ],
            "quicParams": {
                "congestion": "brutal", "brutalUp": "30 mbps", "brutalDown": "40 mbps",
                "maxIdleTimeout": 20, "keepAlivePeriod": 5, "disablePathMTUDiscovery": true,
            },
        });
        let evasion = parse_finalmask(&mask, "x").unwrap();
        assert_eq!(evasion.udp_salamander.as_deref(), Some("obfs-secret"));
        let hop = evasion.udp_hop.unwrap();
        assert_eq!(hop.interval_secs, (5, 10));
        assert_eq!(hop.all_ports(), vec![443, 20000, 20001, 20002]);
        let quic = evasion.quic.unwrap();
        assert_eq!(quic.congestion, QuicCongestion::Brutal);
        assert_eq!(quic.up_bytes_per_sec, 30 * 1024 * 1024 / 8);
        assert_eq!(quic.max_idle_secs, Some(20));
        assert!(quic.disable_mtu_discovery);
    }

    #[test]
    fn udp_masks_that_cannot_be_carried_out_are_refused_not_dropped() {
        for mask in [
            serde_json::json!({"udp": [{"type": "salamander", "settings": {"password": "ab"}}]}),
            serde_json::json!({"udp": [{"type": "salamander", "settings": {"password": "long-enough", "packetSize": "512-1200"}}]}),
            serde_json::json!({"udp": [{"type": "udphop", "settings": {"mode": "intervalremote", "remotePorts": "1-2"}}]}),
            serde_json::json!({"udp": [{"type": "udphop", "settings": {"interval": "1-2", "remotePorts": "1-2"}}]}),
            serde_json::json!({"udp": [{"type": "udphop", "settings": {}}]}),
            serde_json::json!({"udp": [{"type": "xdns", "settings": {}}]}),
            serde_json::json!({"quicParams": {"maxIdleTimeout": 1}}),
            serde_json::json!({"quicParams": {"congestion": "cubic-ish"}}),
        ] {
            assert!(parse_finalmask(&mask, "x").is_err(), "{mask}");
        }
    }

    #[test]
    fn xray_hysteria_configs_become_hysteria2_ones() {
        let outbound = serde_json::json!({
            "tag": "h", "protocol": "hysteria",
            "settings": {"version": 2, "address": "203.0.113.5", "port": 8443},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": "front.example"},
                "hysteriaSettings": {"version": 2, "auth": "secret-auth"},
                "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}]},
            },
        });
        let config = serde_json::json!({"inbounds": [], "outbounds": [outbound]});
        let (parsed, _) = parse_config(&config).unwrap();
        let OutboundProtocol::Hysteria2(hy) = &parsed.outbounds[0].protocol else {
            panic!("expected a Hysteria 2 outbound");
        };
        assert_eq!(&*hy.password, "secret-auth");
        assert_eq!(hy.obfs_password.as_deref(), Some("obfs-secret"));
        assert_eq!(hy.port, 8443);

        let wrong = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "hysteria", "settings": {"version": 1, "address": "a.example", "port": 1},
            }],
        });
        assert!(parse_config(&wrong).is_err());
    }

    #[test]
    fn a_salamander_mask_on_a_tcp_protocol_is_refused() {
        let config = serde_json::json!({"inbounds": [], "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "a.example", "port": 443,
                "users": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}]}]},
            "streamSettings": {"network": "raw",
                "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}]}},
        }]});
        assert!(parse_config(&config)
            .unwrap_err()
            .contains("Hysteria 2 only"));
    }

    #[test]
    fn inbound_ports_may_be_ranges_and_lists() {
        let config = serde_json::json!({
            "inbounds": [{"tag": "many", "protocol": "socks", "listen": "127.0.0.1", "port": "20000-20002,443"}],
            "outbounds": [{"protocol": "freedom"}],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        let ports: Vec<u16> = parsed.inbounds.iter().map(|i| i.port).collect();
        assert_eq!(ports, vec![20000, 20001, 20002, 443]);
        assert!(parsed.inbounds.iter().all(|i| &*i.tag == "many"));
        let too_wide = serde_json::json!({
            "inbounds": [{"tag": "x", "protocol": "socks", "port": "1000-9000"}],
            "outbounds": [{"protocol": "freedom"}],
        });
        assert!(parse_config(&too_wide).is_err());
    }

    #[test]
    fn dokodemo_reads_both_networks_and_the_transparent_options() {
        let config = serde_json::json!({
            "inbounds": [
                {"tag": "t", "protocol": "dokodemo-door", "port": 12346,
                 "settings": {"network": "tcp,udp", "followRedirect": true},
                 "streamSettings": {"sockopt": {"tproxy": "tproxy"}}},
                {"tag": "d", "protocol": "dokodemo-door", "port": 5353,
                 "settings": {"address": "1.1.1.1", "port": 53, "network": "udp"}},
            ],
            "outbounds": [{"protocol": "freedom"}],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        match &parsed.inbounds[0].protocol {
            InboundProtocol::Dokodemo {
                address: None,
                port: None,
                tcp: true,
                udp: true,
                follow_redirect: true,
                ..
            } => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(parsed.inbounds[0].sockopt.tproxy, Tproxy::Tproxy);
        assert!(matches!(
            parsed.inbounds[1].protocol,
            InboundProtocol::Dokodemo {
                address: Some(_),
                port: Some(53),
                tcp: false,
                udp: true,
                follow_redirect: false,
                ..
            }
        ));
        for bad in [
            serde_json::json!({"network": "icmp"}),
            serde_json::json!({"network": "tcp"}),
        ] {
            let tproxy = if bad["network"] == "tcp" {
                "sideways"
            } else {
                "off"
            };
            let config = serde_json::json!({
                "inbounds": [{"protocol": "dokodemo-door", "port": 1, "settings": bad,
                    "streamSettings": {"sockopt": {"tproxy": tproxy}}}],
                "outbounds": [{"protocol": "freedom"}],
            });
            assert!(parse_config(&config).is_err(), "{config}");
        }
    }

    #[test]
    fn dokodemo_destination_follows_port_map_then_rewrites_then_the_fixed_target() {
        let config = serde_json::json!({
            "inbounds": [
                {"tag": "m", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": "5000-5001",
                 "settings": {"portMap": {"5001": "10.0.0.9:853"}, "rewriteAddress": "192.0.2.1",
                              "followRedirect": true, "allowedNetwork": "tcp"}},
                {"tag": "f", "protocol": "dokodemo-door", "port": 5300,
                 "settings": {"address": "1.1.1.1", "port": 53}},
            ],
            "outbounds": [{"protocol": "freedom"}],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        let original: std::net::SocketAddr = "203.0.113.5:8443".parse().unwrap();
        let (a, b, fixed) = (
            &parsed.inbounds[0],
            &parsed.inbounds[1],
            &parsed.inbounds[2],
        );
        // Port 5000 is not in the map: the original, with its address rewritten.
        assert_eq!(
            a.dokodemo_destination(Some(original)),
            Some((Address::parse_host("192.0.2.1"), 8443))
        );
        // Without a redirect there is no port to rewrite into: nothing to dial.
        assert_eq!(a.dokodemo_destination(None), None);
        // Port 5001 is mapped, whatever else is set.
        assert_eq!(
            b.dokodemo_destination(Some(original)),
            Some((Address::parse_host("10.0.0.9"), 853))
        );
        assert_eq!(
            fixed.dokodemo_destination(None),
            Some((Address::parse_host("1.1.1.1"), 53))
        );
        let bad = serde_json::json!({
            "inbounds": [{"protocol": "dokodemo-door", "port": 1,
                          "settings": {"portMap": {"1": "no-port"}}}],
            "outbounds": [{"protocol": "freedom"}],
        });
        assert!(parse_config(&bad).is_err());
    }

    #[test]
    fn a_wireguard_inbound_reads_its_peers() {
        let key = |byte: u8| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([byte; 32])
        };
        let config = |peers: serde_json::Value| {
            serde_json::json!({
                "inbounds": [{"protocol": "wireguard", "port": 51820,
                    "settings": {"secretKey": key(1), "peers": peers}}],
                "outbounds": [{"protocol": "freedom"}],
            })
        };
        let (parsed, _) = parse_config(&config(serde_json::json!([
            {"publicKey": key(2), "allowedIPs": ["10.7.0.2/32"], "keepAlive": 25, "email": "a@x"},
            {"publicKey": key(3), "preSharedKey": key(4)},
        ])))
        .unwrap();
        let InboundProtocol::WireGuard(wg) = &parsed.inbounds[0].protocol else {
            panic!("not a wireguard inbound");
        };
        assert_eq!(wg.mtu, 1420, "Xray's default");
        assert_eq!(wg.peers[0].keepalive, Some(25));
        assert_eq!(wg.peers[0].allowed_ips.len(), 1);
        assert_eq!(wg.peers[0].email.as_deref(), Some("a@x"));
        assert_eq!(wg.peers[1].allowed_ips.len(), 2, "any address by default");
        assert_eq!(wg.peers[1].preshared_key, Some([4; 32]));
        // The key must never reach a log through the debug form.
        assert!(!format!("{wg:?}").contains(&key(1)));
        for bad in [
            serde_json::json!([]),
            serde_json::json!([{"publicKey": "not-a-key"}]),
            serde_json::json!([{"publicKey": key(2), "allowedIPs": ["nope"]}]),
        ] {
            assert!(parse_config(&config(bad)).is_err());
        }
    }

    #[test]
    fn older_spellings_and_the_dns_and_blackhole_outbounds_are_read() {
        // `splithttpSettings` is the same transport as `xhttpSettings`.
        let config = serde_json::json!({
            "inbounds": [],
            "outbounds": [
                {"tag": "a", "protocol": "vless",
                 "settings": {"vnext": [{"address": "a.example", "port": 443,
                    "users": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}]}]},
                 "streamSettings": {"network": "splithttp", "security": "tls",
                    "tlsSettings": {"serverName": "a.example"},
                    "splithttpSettings": {"path": "/legacy", "host": "front.example"}}},
                {"tag": "d", "protocol": "dns", "settings": {"rules": [
                    {"action": "drop", "qType": "28"},
                    {"action": "return", "rCode": 3, "domain": ["full:x.example"]}]}},
                {"tag": "legacy", "protocol": "dns", "settings": {"blockTypes": [65]}},
                {"tag": "h", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
                {"tag": "n", "protocol": "blackhole"},
            ],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        let Transport::Xhttp(xhttp) = &parsed.outbounds[0].stream.transport else {
            panic!("not xhttp");
        };
        assert_eq!(
            &*xhttp.path, "/legacy",
            "the older name must not be ignored"
        );
        let OutboundProtocol::Dns { rules } = &parsed.outbounds[1].protocol else {
            panic!("not dns");
        };
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, DnsAction::Drop);
        assert_eq!(&*rules[0].qtypes, &[28]);
        assert_eq!(rules[1].action, DnsAction::Return(3));
        let OutboundProtocol::Dns { rules } = &parsed.outbounds[2].protocol else {
            panic!("not dns");
        };
        assert_eq!(
            rules[0].action,
            DnsAction::Return(5),
            "legacy reject is REFUSED"
        );
        assert!(matches!(
            &parsed.outbounds[3].protocol,
            OutboundProtocol::Blackhole { response: Some(bytes) } if bytes.starts_with(b"HTTP/1.1 403")
        ));
        assert!(matches!(
            parsed.outbounds[4].protocol,
            OutboundProtocol::Blackhole { response: None }
        ));
        // A rule that would forward the query is refused, not ignored.
        let bad = serde_json::json!({"inbounds": [], "outbounds": [
            {"protocol": "dns", "settings": {"rules": [{"action": "direct"}]}}]});
        assert!(parse_config(&bad).is_err());
    }

    #[test]
    fn hysteria2_masquerade_is_read_from_either_spelling() {
        let native = serde_json::json!({"inbounds": [{"protocol": "hysteria2", "port": 443,
            "settings": {"password": "pw", "masquerade": {"type": "proxy", "url": "https://example.org"}},
            "streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificate": ["-----BEGIN CERTIFICATE-----", "AAAA", "-----END CERTIFICATE-----"], "key": ["-----BEGIN PRIVATE KEY-----", "AAAA", "-----END PRIVATE KEY-----"]}]}}}], "outbounds": [{"protocol": "freedom"}]});
        let xray = serde_json::json!({"inbounds": [{"protocol": "hysteria", "port": 443,
            "settings": {"version": 2, "clients": [{"auth": "pw"}]},
            "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"certificates": [{"certificate": ["-----BEGIN CERTIFICATE-----", "AAAA", "-----END CERTIFICATE-----"], "key": ["-----BEGIN PRIVATE KEY-----", "AAAA", "-----END PRIVATE KEY-----"]}]}, "hysteriaSettings": {"version": 2, "auth": "pw",
                "masquerade": {"type": "string", "content": "hi", "statusCode": 404,
                               "headers": {"x-a": "b"}}}}}],
            "outbounds": [{"protocol": "freedom"}]});
        let (a, _) = parse_config(&native).unwrap();
        let InboundProtocol::Hysteria2(a) = &a.inbounds[0].protocol else {
            panic!()
        };
        assert_eq!(
            a.masquerade,
            Some(Hysteria2Masquerade::Proxy {
                url: "https://example.org".into()
            })
        );
        let (b, _) = parse_config(&xray).unwrap();
        let InboundProtocol::Hysteria2(b) = &b.inbounds[0].protocol else {
            panic!()
        };
        assert!(matches!(
            &b.masquerade,
            Some(Hysteria2Masquerade::Text { status: 404, content, .. }) if &**content == "hi"
        ));
        let bad = serde_json::json!({"inbounds": [{"protocol": "hysteria2", "port": 443,
            "settings": {"password": "pw", "masquerade": {"type": "file"}},
            "streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificate": ["-----BEGIN CERTIFICATE-----", "AAAA", "-----END CERTIFICATE-----"], "key": ["-----BEGIN PRIVATE KEY-----", "AAAA", "-----END PRIVATE KEY-----"]}]}}}],
            "outbounds": [{"protocol": "freedom"}]});
        assert!(
            parse_config(&bad).is_err(),
            "a file masquerade needs its directory"
        );
    }

    #[test]
    fn the_simplified_outbound_form_means_the_same_as_the_nested_one() {
        let id = "5783a3e7-e373-51cd-8642-c83782b807c5";
        let parse = |settings: serde_json::Value, protocol: &str| {
            let config = serde_json::json!({"inbounds": [], "outbounds": [
                {"protocol": protocol, "settings": settings,
                 "streamSettings": {"network": "raw", "security": "tls",
                                    "tlsSettings": {"serverName": "a.example"}}}]});
            parse_config(&config).unwrap().0.outbounds[0]
                .protocol
                .clone()
        };
        let flat = parse(
            serde_json::json!({"address": "198.51.100.7", "port": 8443, "id": id,
                               "encryption": "none", "flow": "xtls-rprx-vision"}),
            "vless",
        );
        let nested = parse(
            serde_json::json!({"vnext": [{"address": "198.51.100.7", "port": 8443,
                "users": [{"id": id, "encryption": "none", "flow": "xtls-rprx-vision"}]}]}),
            "vless",
        );
        assert_eq!(flat, nested);
        for (protocol, flat_settings) in [
            (
                "vmess",
                serde_json::json!({"address": "198.51.100.7", "port": 1, "id": id}),
            ),
            (
                "trojan",
                serde_json::json!({"address": "198.51.100.7", "port": 1, "password": "pw"}),
            ),
            (
                "shadowsocks",
                serde_json::json!({"address": "198.51.100.7", "port": 1,
                                   "method": "aes-256-gcm", "password": "pw"}),
            ),
        ] {
            // Each reads without error and names the server it was given.
            let parsed = parse(flat_settings, protocol);
            assert_eq!(parsed.name(), protocol);
        }
        // A flat reverse account makes a bridge, as the nested one does.
        let config = serde_json::json!({"inbounds": [], "outbounds": [{"tag": "link",
            "protocol": "vless", "settings": {"address": "198.51.100.7", "port": 443, "id": id,
                "reverse": {"tag": "r"}}}]});
        let bridges = parse_config(&config).unwrap().0.bridges;
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].via.as_deref(), Some("link"));
    }

    #[test]
    fn custom_sockopts_are_read_with_xrays_defaults() {
        use zero_core::custom_sockopt::CustomValue;
        let config = |list: serde_json::Value| {
            serde_json::json!({"inbounds": [], "outbounds": [{"protocol": "freedom",
                "streamSettings": {"sockopt": {"customSockopt": list}}}]})
        };
        let (parsed, _) = parse_config(&config(serde_json::json!([
            {"opt": "13", "value": "bbr", "type": "str", "network": "tcp"},
            {"level": 1, "opt": 8, "value": "212992", "type": "int", "system": "linux"},
        ])))
        .unwrap();
        let custom = &parsed.outbounds[0].stream.sockopt.custom;
        assert_eq!(
            (custom[0].level, custom[0].opt),
            (6, 13),
            "the level defaults to TCP"
        );
        assert_eq!(custom[0].value, CustomValue::Bytes(b"bbr".to_vec()));
        assert_eq!(custom[0].network, "tcp");
        assert_eq!(
            (custom[1].level, custom[1].value.clone()),
            (1, CustomValue::Int(212992))
        );
        assert_eq!(custom[1].system.as_deref(), Some("linux"));
        for bad in [
            serde_json::json!([{"value": "1", "type": "int"}]),
            serde_json::json!([{"opt": "x", "value": "1", "type": "int"}]),
            serde_json::json!([{"opt": "1", "value": "1", "type": "float"}]),
        ] {
            assert!(parse_config(&config(bad)).is_err());
        }
    }

    #[test]
    fn send_through_names_the_address_to_leave_from() {
        let parse = |value: serde_json::Value| {
            parse_config(&serde_json::json!({
                "inbounds": [], "outbounds": [{"protocol": "freedom", "sendThrough": value}]
            }))
        };
        let (parsed, _) = parse(serde_json::json!("192.0.2.7")).unwrap();
        assert_eq!(
            parsed.outbounds[0].stream.sockopt.bind_address,
            Some("192.0.2.7".parse().unwrap())
        );
        for system_choice in ["", "0.0.0.0"] {
            let (parsed, _) = parse(serde_json::json!(system_choice)).unwrap();
            assert_eq!(parsed.outbounds[0].stream.sockopt.bind_address, None);
        }
        assert!(parse(serde_json::json!("origin")).is_err());
        assert!(parse(serde_json::json!("not-an-ip")).is_err());
    }

    #[test]
    fn an_empty_ech_config_list_means_none() {
        let config = serde_json::json!({"inbounds": [], "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "a.example", "port": 443,
                "users": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}]}]},
            "streamSettings": {"network": "raw", "security": "tls",
                "tlsSettings": {"serverName": "a.example", "echConfigList": ""}},
        }]});
        let (parsed, _) = parse_config(&config).unwrap();
        let Security::Tls(tls) = &parsed.outbounds[0].stream.security else {
            panic!("expected TLS");
        };
        assert!(tls.ech.is_none());
    }

    /// Xray writes an inline certificate and key as arrays of PEM lines, the
    /// shape `xray tls cert` prints; every line has to be read, not the first.
    #[test]
    fn an_inline_certificate_written_as_pem_lines_is_read_whole() {
        let lines = |text: &str| -> Vec<Value> { text.lines().map(Value::from).collect() };
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----";
        let key = "-----BEGIN PRIVATE KEY-----\nCCCC\n-----END PRIVATE KEY-----";
        let entry = serde_json::json!({"certificate": lines(pem), "key": lines(key)});
        assert_eq!(read_certificate_blob(&entry, "x").unwrap(), pem.as_bytes());
        assert_eq!(read_key_blob(&entry, "x").unwrap(), key.as_bytes());
        // One element holding it all is the same text.
        let whole = serde_json::json!({"certificate": [pem], "key": [key]});
        assert_eq!(read_certificate_blob(&whole, "x").unwrap(), pem.as_bytes());
        assert!(read_certificate_blob(&serde_json::json!({"certificate": []}), "x").is_err());
    }

    #[test]
    fn socket_options_are_read_in_xrays_conventions() {
        let sockopt =
            |text: &str| parse_sockopt(&serde_json::from_str::<Value>(text).unwrap(), "x").unwrap();
        let all = sockopt(
            r#"{"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 10, "tcpUserTimeout": 9000,
                "tcpWindowClamp": 65000, "tcpMaxSeg": 1300, "tcpMptcp": true, "V6Only": true}"#,
        );
        assert_eq!(all.keepalive, Some((30, 10)));
        assert_eq!(all.user_timeout_ms, Some(9000));
        assert_eq!(all.window_clamp, Some(65000));
        assert_eq!(all.max_seg, Some(1300));
        assert!(all.mptcp);
        assert_eq!(all.v6_only, Some(true));
        // Zero is the default; one given makes the other default too.
        assert_eq!(
            sockopt(r#"{"tcpKeepAliveIdle": 0}"#).keepalive,
            Some((45, 45))
        );
        assert_eq!(
            sockopt(r#"{"tcpKeepAliveInterval": 5}"#).keepalive,
            Some((45, 5))
        );
        // Negative turns it off.
        assert_eq!(
            sockopt(r#"{"tcpKeepAliveIdle": -1}"#).keepalive,
            Some((0, 0))
        );
        assert_eq!(sockopt("{}"), Sockopt::default());
    }

    #[test]
    fn an_inbound_keeps_its_socket_options() {
        let config = serde_json::json!({
            "inbounds": [{
                "tag": "in", "port": 1080, "protocol": "socks",
                "streamSettings": {"sockopt": {"tcpKeepAliveIdle": 20, "tcpMptcp": true}},
            }],
            "outbounds": [{"protocol": "freedom"}],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        assert_eq!(parsed.inbounds[0].sockopt.keepalive, Some((20, 45)));
        assert!(parsed.inbounds[0].sockopt.mptcp);
    }

    #[test]
    fn sections_that_are_accepted_and_not_applied_are_named() {
        let config = serde_json::json!({
            "stats": {}, "api": {"tag": "api", "services": ["StatsService"]},
            "metrics": {"tag": "m"},
            "log": {"loglevel": "info", "access": "/var/log/x.log"},
            "inbounds": [],
            "outbounds": [{"protocol": "vless",
                "settings": {"vnext": [{"address": "a.example", "port": 443,
                    "users": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}]}]},
                "streamSettings": {"network": "raw", "security": "tls",
                    "tlsSettings": {"serverName": "a.example", "minVersion": "1.2",
                        "cipherSuites": "TLS_AES_128_GCM_SHA256", "enableSessionResumption": false}}}],
            "policy": {"levels": {"0": {"bufferSize": 4}, "1": {}}, "system": {}},
        });
        let (_, out) = parse_config(&config).unwrap();
        let paths: Vec<&str> = out.diagnostics.iter().map(|d| d.path.as_str()).collect();
        for expected in [
            "stats",
            "api",
            "metrics",
            "log.access",
            "policy.levels",
            "policy.system",
            "policy.levels.0.bufferSize",
        ] {
            assert!(
                paths.contains(&expected),
                "no note for {expected}: {paths:?}"
            );
        }
        assert!(paths.iter().any(|p| p.ends_with("tlsSettings.minVersion")));
        assert!(paths
            .iter()
            .any(|p| p.ends_with("tlsSettings.cipherSuites")));
        // A setting that says "off" is not a request, so no note for it.
        assert!(!paths.iter().any(|p| p.ends_with("enableSessionResumption")));
    }

    #[test]
    fn policy_and_burst_observatory_are_read() {
        let config = serde_json::json!({
            "policy": {"levels": {"0": {
                "handshake": 8, "connIdle": 120, "uplinkOnly": 2, "downlinkOnly": 5}}},
            "burstObservatory": {
                "subjectSelector": ["proxy"],
                "pingConfig": {"destination": "https://www.gstatic.com/generate_204",
                               "interval": "90s", "sampling": 3, "timeout": "5s"}},
            "inbounds": [],
            "outbounds": [{"protocol": "freedom"}],
        });
        let (parsed, _) = parse_config(&config).unwrap();
        assert_eq!(parsed.policy.handshake, std::time::Duration::from_secs(8));
        assert_eq!(parsed.policy.conn_idle, std::time::Duration::from_secs(120));
        assert_eq!(parsed.policy.half_close, std::time::Duration::from_secs(5));
        let observatory = parsed.observatory.expect("an observatory");
        assert_eq!(
            &*observatory.probe_url,
            "https://www.gstatic.com/generate_204"
        );
        assert_eq!(
            observatory.probe_interval,
            std::time::Duration::from_secs(90)
        );
        assert_eq!(&*observatory.subject_selector[0], "proxy");
    }
}
