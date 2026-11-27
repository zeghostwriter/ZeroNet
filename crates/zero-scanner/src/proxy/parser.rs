use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub protocol: String, // "vless", "trojan", "vmess"
    pub id_or_password: String,
    pub address: String,
    pub port: u16,
    pub transport: String, // "tcp", "ws", "grpc", "xhttp"
    pub path: String,
    pub host: String,
    pub sni: String,
    pub security: String, // "tls", "reality", "none"
    pub alpn: Vec<String>,
    pub remark: String,
}

impl ProxyConfig {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("vless://") {
            parse_vless_or_trojan(trimmed, "vless")
        } else if lower.starts_with("trojan://") {
            parse_vless_or_trojan(trimmed, "trojan")
        } else if lower.starts_with("vmess://") {
            parse_vmess(trimmed)
        } else {
            Err(format!("Unsupported proxy URL scheme in: {}", raw))
        }
    }

    pub fn to_share_url(&self, override_ip: Option<&str>, override_port: Option<u16>) -> String {
        let address = override_ip.unwrap_or(&self.address);
        let port = override_port.unwrap_or(self.port);
        // IPv6 literals must be bracketed in the authority.
        let host = if address.contains(':') && !address.starts_with('[') {
            format!("[{}]", address)
        } else {
            address.to_string()
        };

        if self.protocol == "vmess" {
            // VMess links are base64 JSON, not URLs.
            let json = serde_json::json!({
                "v": "2",
                "ps": self.remark,
                "add": address,
                "port": port.to_string(),
                "id": self.id_or_password,
                "aid": "0",
                "net": self.transport,
                "type": "none",
                "host": self.host,
                "path": self.path,
                "tls": if self.security == "tls" { "tls" } else { "" },
                "sni": self.sni,
            });
            return format!("vmess://{}", BASE64.encode(json.to_string()));
        }

        let mut params = Vec::new();
        if !self.transport.is_empty() && self.transport != "tcp" {
            params.push(format!("type={}", encode(&self.transport)));
        }
        if !self.security.is_empty() {
            params.push(format!("security={}", encode(&self.security)));
        }
        if !self.sni.is_empty() {
            params.push(format!("sni={}", encode(&self.sni)));
        }
        if !self.host.is_empty() {
            params.push(format!("host={}", encode(&self.host)));
        }
        if !self.path.is_empty() {
            params.push(format!("path={}", encode(&self.path)));
        }
        if !self.alpn.is_empty() {
            params.push(format!("alpn={}", encode(&self.alpn.join(","))));
        }
        let query_str = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };

        let fragment = if self.remark.is_empty() {
            String::new()
        } else {
            format!("#{}", encode(&self.remark))
        };

        format!(
            "{}://{}@{}:{}{}{}",
            self.protocol,
            encode(&self.id_or_password),
            host,
            port,
            query_str,
            fragment
        )
    }
}

/// Percent-encodes a URL component. The old encoder only escaped `/ ? &`,
/// so remarks or paths containing `#`, `%`, spaces or non-ASCII produced
/// links that parsed back to different values.
fn encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// Decodes `%XX` escapes (the URL fragment is kept encoded by `url`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(v) = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_vless_or_trojan(raw: &str, protocol: &str) -> Result<ProxyConfig, String> {
    let parsed = Url::parse(raw).map_err(|e| format!("Invalid URL: {}", e))?;
    let id_or_password = percent_decode(parsed.username());
    if id_or_password.is_empty() {
        return Err("Missing UUID or password in proxy URL".to_string());
    }

    let address = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let remark = percent_decode(parsed.fragment().unwrap_or(""));

    let mut transport = "tcp".to_string();
    let mut path = "/".to_string();
    let mut host = address.clone();
    let mut sni = address.clone();
    let mut security = "tls".to_string();
    let mut alpn = Vec::new();

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "type" => transport = v.to_string(),
            "path" => path = v.to_string(),
            "host" => host = v.to_string(),
            "sni" => sni = v.to_string(),
            "security" => security = v.to_string(),
            "alpn" => alpn = v.split(',').map(|s| s.trim().to_string()).collect(),
            _ => {}
        }
    }

    if sni.is_empty() && !host.is_empty() {
        sni = host.clone();
    }
    if host.is_empty() && !sni.is_empty() {
        host = sni.clone();
    }

    Ok(ProxyConfig {
        protocol: protocol.to_string(),
        id_or_password,
        address,
        port,
        transport,
        path,
        host,
        sni,
        security,
        alpn,
        remark,
    })
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VMessJson {
    v: Option<String>,
    ps: Option<String>,
    add: Option<String>,
    port: Option<serde_json::Value>,
    id: Option<String>,
    net: Option<String>,
    path: Option<String>,
    host: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
}

fn parse_vmess(raw: &str) -> Result<ProxyConfig, String> {
    let b64 = raw.get("vmess://".len()..).unwrap_or("").trim();
    // Share links come both padded and unpadded.
    let decoded = BASE64
        .decode(b64)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64.trim_end_matches('='))
        })
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    let json: VMessJson =
        serde_json::from_slice(&decoded).map_err(|e| format!("JSON parse failed: {}", e))?;

    let address = json.add.unwrap_or_default();
    let port = match json.port {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(443),
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(443),
        _ => 443,
    };

    let host = json.host.unwrap_or_else(|| address.clone());
    let sni = json.sni.unwrap_or_else(|| host.clone());
    let security = if json.tls.as_deref() == Some("tls") {
        "tls".to_string()
    } else {
        "none".to_string()
    };

    Ok(ProxyConfig {
        protocol: "vmess".to_string(),
        id_or_password: json.id.unwrap_or_default(),
        address,
        port,
        transport: json.net.unwrap_or_else(|| "tcp".to_string()),
        path: json.path.unwrap_or_else(|| "/".to_string()),
        host,
        sni,
        security,
        alpn: Vec::new(),
        remark: json.ps.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless() {
        let url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fws#MyNode";
        let cfg = ProxyConfig::parse(url).unwrap();
        assert_eq!(cfg.protocol, "vless");
        assert_eq!(cfg.address, "example.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.transport, "ws");
        assert_eq!(cfg.sni, "example.com");
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.remark, "MyNode");
    }
}

#[cfg(test)]
mod share_url_tests {
    use super::*;

    #[test]
    fn share_url_round_trips_special_characters() {
        let url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&security=tls&sni=example.com&host=cdn.example.com&path=%2Fws%3Fed%3D2048#My%20Node%20%231";
        let cfg = ProxyConfig::parse(url).unwrap();
        let out = cfg.to_share_url(Some("104.16.1.1"), Some(8443));
        let back = ProxyConfig::parse(&out).unwrap();
        assert_eq!(back.address, "104.16.1.1");
        assert_eq!(back.port, 8443);
        assert_eq!(back.path, "/ws?ed=2048");
        assert_eq!(back.host, "cdn.example.com");
        assert_eq!(cfg.remark, "My Node #1");
        assert_eq!(back.remark, "My Node #1");
    }

    #[test]
    fn vmess_share_url_is_base64_json() {
        let json = r#"{"v":"2","ps":"n","add":"a.com","port":"443","id":"u","net":"ws","host":"h","path":"/p","tls":"tls","sni":"s"}"#;
        let cfg = ProxyConfig::parse(&format!("vmess://{}", BASE64.encode(json))).unwrap();
        let out = cfg.to_share_url(Some("104.16.1.1"), None);
        let back = ProxyConfig::parse(&out).unwrap();
        assert_eq!(back.address, "104.16.1.1");
        assert_eq!(back.path, "/p");
        assert_eq!(back.security, "tls");
    }

    #[test]
    fn non_ascii_scheme_prefix_does_not_panic() {
        assert!(ProxyConfig::parse("VMESS://ééé").is_err());
    }
}
