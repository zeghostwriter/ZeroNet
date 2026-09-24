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
    let outbounds = parse_outbounds(outbounds, &mut out)?;

    let routing = match obj.get("routing") {
        Some(r) => parse_routing(r, &mut out)?,
        None => Routing::default(),
    };

    let dns = match obj.get("dns") {
        Some(d) => parse_dns(d, &mut out)?,
        None => DnsSettings::default(),
    };

    let observatory = obj
        .get("observatory")
        .map(|value| parse_observatory(value, "observatory"))
        .transpose()?;

    let assets = obj
        .get("assets")
        .map(|value| parse_assets(value, "assets"))
        .transpose()?;

    let cfg = RuntimeConfig {
        inbounds: inbounds.into_boxed_slice(),
        outbounds: outbounds.into_boxed_slice(),
        routing,
        dns,
        observatory,
        assets,
        log_level,
    };
    cfg.validate()?;
    Ok((cfg, out))
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
    arr.iter()
        .enumerate()
        .map(|(i, v)| parse_inbound(v, i, out))
        .collect()
}

fn parse_inbound(v: &Value, idx: usize, _out: &mut ParseOutput) -> R<Inbound> {
    let path = format!("inbounds[{idx}]");
    let proto = v.get("protocol").and_then(Value::as_str).unwrap_or("");
    let protocol = match proto {
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
        "hysteria2" => {
            InboundProtocol::Hysteria2(parse_hysteria2_inbound(v.get("settings"), &path)?)
        }
        "tuic" => InboundProtocol::Tuic(parse_tuic_inbound(v.get("settings"), &path)?),
        "tun" => InboundProtocol::Tun(parse_tun_inbound(v.get("settings"), &path)?),
        "dokodemo-door" => {
            let s = v.get("settings");
            let target = match (
                s.and_then(|s| s.get("address")).and_then(Value::as_str),
                s.and_then(|s| s.get("port")).and_then(json_port),
            ) {
                (Some(a), Some(p)) => Some((Address::parse_host(a), p)),
                _ => None,
            };
            let network = match s.and_then(|s| s.get("network")).and_then(Value::as_str) {
                Some("udp") => Network::Udp,
                _ => Network::Tcp,
            };
            InboundProtocol::Dokodemo { target, network }
        }
        "" => {
            // Placeholder / empty inbound or API inbound tag
            InboundProtocol::Dokodemo {
                target: None,
                network: Network::Tcp,
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
                route_only: s.get("routeOnly").and_then(Value::as_bool).unwrap_or(false),
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
    })
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
            let config = parse_xhttp(v.get("xhttpSettings"), v, path)?;
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
            let certificate_value = tls
                .get("certificates")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .ok_or_else(|| {
                    format!("{path}.streamSettings.tlsSettings.certificates is required")
                })?;
            let certificate = read_certificate_blob(certificate_value, path)?;
            let private_key = read_key_blob(certificate_value, path)?;
            let alpn = tls
                .get("alpn")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(Box::from).collect())
                .unwrap_or_default();
            Ok(InboundSecurity::Tls(InboundTlsConfig {
                certificate: certificate.into_boxed_slice(),
                private_key: private_key.into_boxed_slice(),
                alpn,
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
            Ok(InboundSecurity::Reality(InboundRealityConfig {
                server_names: server_names.into_boxed_slice(),
                private_key,
                short_ids: short_ids.into_boxed_slice(),
                target,
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

fn read_certificate_blob(certificate: &Value, path: &str) -> R<Vec<u8>> {
    if let Some(file) = certificate.get("certificateFile").and_then(Value::as_str) {
        return std::fs::read(file)
            .map_err(|e| format!("{path}: reading certificateFile {file:?}: {e}"));
    }
    if let Some(inline) = certificate.get("certificate").and_then(Value::as_array) {
        return inline
            .iter()
            .filter_map(Value::as_str)
            .map(|value| value.as_bytes().to_vec())
            .next()
            .ok_or_else(|| format!("{path}: certificate array is empty"));
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
        return inline
            .iter()
            .filter_map(Value::as_str)
            .map(|value| value.as_bytes().to_vec())
            .next()
            .ok_or_else(|| format!("{path}: key array is empty"));
    }
    Err(format!("{path}: keyFile or key is required"))
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
        users.push(VlessInboundUser { uuid, flow });
    }
    if users.is_empty() {
        return Err(format!("{path}.settings.clients must not be empty"));
    }
    Ok(VlessInboundConfig {
        users: users.into_boxed_slice(),
    })
}

fn parse_trojan_inbound(settings: Option<&Value>, path: &str) -> R<TrojanInboundConfig> {
    let clients = settings
        .and_then(|s| s.get("clients"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}.settings.clients is required for trojan"))?;
    let mut password_hashes = Vec::with_capacity(clients.len());
    for (idx, client) in clients.iter().enumerate() {
        let client_path = format!("{path}.settings.clients[{idx}]");
        let password = client
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{client_path}.password is required"))?;
        password_hashes.push(crate::trojan_hash(password));
    }
    if password_hashes.is_empty() {
        return Err(format!("{path}.settings.clients must not be empty"));
    }
    Ok(TrojanInboundConfig {
        password_hashes: password_hashes.into_boxed_slice(),
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
            Ok(VmessInboundUser { uuid, cipher })
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

fn parse_outbound(v: &Value, idx: usize, out: &mut ParseOutput) -> R<Outbound> {
    let path = format!("outbounds[{idx}]");
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
        // Evasion is the one thing a link cannot express, because it is a
        // property of this network rather than of the server. Allow it to be
        // layered on without re-describing the whole outbound.
        if let Some(evasion) = v.get("evasion") {
            let overlay = parse_link_evasion(evasion, &path)?;
            if overlay.tcp_fragment.is_some() {
                outbound.stream.evasion.tcp_fragment = overlay.tcp_fragment;
            }
            if !overlay.udp_noise.is_empty() {
                outbound.stream.evasion.udp_noise = overlay.udp_noise;
            }
            if overlay.keepalive.is_some() {
                outbound.stream.evasion.keepalive = overlay.keepalive;
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
        "blackhole" => OutboundProtocol::Blackhole,
        "dns" => OutboundProtocol::Dns,
        "vless" => parse_vless(settings, &path)?,
        "trojan" => parse_trojan(settings, &path)?,
        "shadowsocks" => parse_shadowsocks(settings, &path)?,
        "vmess" => parse_vmess(settings, &path)?,
        "anytls" => parse_anytls(settings, &path)?,
        "hysteria2" => parse_hysteria2(settings, &path)?,
        "tuic" => parse_tuic(settings, &path)?,
        "wireguard" | "amnezia-wg" | "amneziawg" => parse_amnezia_wireguard(settings, &path)?,
        "" => {
            // Empty outbound protocol placeholder often generated by clients like Qv2ray for dummy proxy node
            OutboundProtocol::Blackhole
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

    let ob = Outbound {
        tag,
        protocol,
        stream,
        mux,
    };
    ob.validate()?;
    Ok(ob)
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
    Ok(MuxConfig {
        enabled,
        max_concurrency,
    })
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
    Ok(OutboundProtocol::Hysteria2(Hysteria2Config {
        address: Address::parse_host(address),
        port,
        password: password.into(),
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

fn parse_amnezia_wireguard(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
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

    Ok(OutboundProtocol::AmneziaWireguard(AmneziaWireguardConfig {
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
    parse_wireguard_key(Some(value), path).map(Some)
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
    Ok(Hysteria2InboundConfig {
        passwords: passwords.into_boxed_slice(),
    })
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

fn parse_stream(v: &Value, path: &str, _out: &mut ParseOutput) -> R<StreamSettings> {
    let network = v.get("network").and_then(Value::as_str).unwrap_or("raw");

    let mut transport = match network {
        "raw" | "tcp" => Transport::Raw,
        "ws" => Transport::WebSocket(parse_ws(v.get("wsSettings"))),
        "httpupgrade" => Transport::HttpUpgrade(parse_ws(v.get("httpupgradeSettings"))),
        "grpc" => Transport::Grpc(parse_grpc(v.get("grpcSettings"))),
        "xhttp" | "splithttp" => Transport::Xhttp(parse_xhttp(v.get("xhttpSettings"), v, path)?),
        other => {
            return Err(format!(
                "{path}.streamSettings.network: unsupported transport {other:?}"
            ))
        }
    };

    let security = match v.get("security").and_then(Value::as_str).unwrap_or("none") {
        "none" => Security::None,
        "tls" => {
            let t = v.get("tlsSettings");
            let allow_insecure = t
                .and_then(|t| t.get("allowInsecure"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ech = parse_ech_config(t, path)?;
            let trusted_roots = parse_trusted_roots(t, path)?;
            Security::Tls(TlsConfig {
                trusted_roots,
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
    let encoded = settings.get("echConfigList");
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

    let Some(encoded) = encoded.and_then(Value::as_str) else {
        // Xray also permits discovery from the HTTPS/SVCB record of the
        // configured public name. The runtime fills this bounded marker from
        // its managed resolver before constructing Rustls.
        return Ok(Some(EchConfig {
            config_list: Box::new([]),
            server_name: inner_name.map(Arc::from),
        }));
    };
    if encoded.trim().is_empty() {
        return Err(format!(
            "{path}.streamSettings.tlsSettings.echConfigList must not be empty"
        ));
    }

    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|error| {
            format!("{path}.streamSettings.tlsSettings.echConfigList is not valid base64: {error}")
        })?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(format!(
            "{path}.streamSettings.tlsSettings.echConfigList must decode to 1..65536 bytes"
        ));
    }

    Ok(Some(EchConfig {
        config_list: bytes.into_boxed_slice(),
        server_name: inner_name.map(Arc::from),
    }))
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
            if let Some(s) = val.as_str() {
                headers.insert(Box::from(k.as_str()), Box::from(s));
            }
        }
    }

    // `host` may live at the top level or inside headers.
    let host = v
        .and_then(|w| w.get("host"))
        .and_then(Value::as_str)
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

pub(crate) fn grpc_path(service: &str) -> String {
    let service = service.trim();
    if service.is_empty() {
        return "/Tun".into();
    }
    if let Some(custom) = service.strip_prefix('/') {
        // Custom path form: the final segment names the stream, and an
        // optional `|` separates the single and multiplexed stream names.
        let (prefix, ending) = match custom.rfind('/') {
            Some(index) => (&custom[..index], &custom[index + 1..]),
            None => ("", custom),
        };
        let method = ending.split('|').next().unwrap_or(ending);
        return if prefix.is_empty() {
            format!("/{method}")
        } else {
            format!("/{prefix}/{method}")
        };
    }
    format!("/{}/Tun", service.trim_matches('/'))
}

fn parse_grpc(v: Option<&Value>) -> WebSocketConfig {
    let mut config = parse_ws(v);
    let service = v
        .and_then(|settings| settings.get("serviceName"))
        .and_then(Value::as_str)
        .unwrap_or("");
    config.path = Arc::from(grpc_path(service));
    if config.host.is_none() {
        config.host = v
            .and_then(|settings| settings.get("authority"))
            .and_then(Value::as_str)
            .map(Arc::from);
    }
    config
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
    if v.get("xhttpSettings")
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
                "fragment" => {
                    ev.tcp_fragment =
                        Some(parse_fragment(s, &format!("{path}.finalmask.tcp[{i}]"))?)
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
                other => {
                    return Err(format!(
                        "{path}.finalmask.udp[{i}].type: unsupported mask {other:?}"
                    ))
                }
            }
        }
    }

    Ok(ev)
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
    Ok(evasion)
}

/// Evasion layered onto a link-form outbound: `{"fragment": {...},
/// "noises": [...]}`. Deliberately the same shape as the Freedom schema so
/// there is one spelling of these knobs across the config surface.
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

    Ok(FragmentConfig {
        packets,
        length: RangeU32::parse(get("length").unwrap_or("100-200"))
            .ok_or_else(|| format!("{path}: bad length"))?,
        delay: RangeDuration::parse_millis(delay_str)
            .ok_or_else(|| format!("{path}: bad delay"))?,
        max_split: RangeU32::parse(get("maxSplit").unwrap_or("0"))
            .ok_or_else(|| format!("{path}: bad maxSplit"))?,
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

fn parse_observatory(v: &Value, path: &str) -> R<ObservatoryConfig> {
    let object = v
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let probe_url: Arc<str> = object
        .get("probeUrl")
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

    let target = if let Some(tag) = v.get("outboundTag").and_then(Value::as_str) {
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

    if let Some(a) = v.get("domain").and_then(Value::as_array) {
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
    if let Some(a) = v.get("source").and_then(Value::as_array) {
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
        rule.networks = n
            .split(',')
            .filter_map(|s| match s.trim() {
                "tcp" => Some(Network::Tcp),
                "udp" => Some(Network::Udp),
                _ => None,
            })
            .collect();
    }
    if let Some(a) = v.get("inboundTag").and_then(Value::as_array) {
        rule.inbound_tags = a.iter().filter_map(Value::as_str).map(Box::from).collect();
    }
    if let Some(a) = v.get("protocol").and_then(Value::as_array) {
        rule.protocols = a.iter().filter_map(Value::as_str).map(Box::from).collect();
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
    })
}

// ------------------------------------------------------------------- dns

fn parse_dns(v: &Value, out: &mut ParseOutput) -> R<DnsSettings> {
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
        leak_policy: LeakPolicy::Strict,
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex: {s:?}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
