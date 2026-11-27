use crate::proxy::ProxyConfig;
use crate::types::ProbeResult;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::json;

pub struct ExportBundle {
    pub endpoints_text: String,
    pub share_urls: Vec<String>,
    pub subscription_base64: String,
    pub singbox_json: String,
    pub clash_yaml: String,
}

pub fn generate_exports(results: &[ProbeResult], proxy_cfg: Option<&ProxyConfig>) -> ExportBundle {
    let mut endpoints_text = String::new();
    let mut share_urls = Vec::new();

    for r in results {
        let ep_str = format!("{}:{}", r.ip, r.port);
        endpoints_text.push_str(&ep_str);
        endpoints_text.push('\n');

        if let Some(cfg) = proxy_cfg {
            let url = cfg.to_share_url(Some(&r.ip.to_string()), Some(r.port));
            share_urls.push(url);
        }
    }

    let subscription_base64 = if !share_urls.is_empty() {
        let joined = share_urls.join("\n");
        BASE64.encode(joined)
    } else {
        String::new()
    };

    let singbox_json = generate_singbox(results, proxy_cfg);
    let clash_yaml = generate_clash(results, proxy_cfg);

    ExportBundle {
        endpoints_text,
        share_urls,
        subscription_base64,
        singbox_json,
        clash_yaml,
    }
}

fn generate_singbox(results: &[ProbeResult], proxy_cfg: Option<&ProxyConfig>) -> String {
    let mut outbounds = Vec::new();

    for (idx, r) in results.iter().enumerate() {
        let tag = format!("CF-{}-{}", r.colo.as_deref().unwrap_or("EDGE"), idx + 1);
        if let Some(cfg) = proxy_cfg {
            let mut outbound = json!({
                "type": cfg.protocol,
                "tag": tag,
                "server": r.ip.to_string(),
                "server_port": r.port,
            });

            match cfg.protocol.as_str() {
                "vless" => outbound["uuid"] = json!(cfg.id_or_password),
                "vmess" => {
                    outbound["uuid"] = json!(cfg.id_or_password);
                    outbound["security"] = json!("auto");
                }
                "trojan" => outbound["password"] = json!(cfg.id_or_password),
                _ => {}
            }

            if cfg.security == "tls" {
                outbound["tls"] = json!({
                    "enabled": true,
                    "server_name": cfg.sni,
                    "insecure": false,
                });
            }

            if cfg.transport == "ws" {
                outbound["transport"] = json!({
                    "type": "ws",
                    "path": cfg.path,
                    "headers": {
                        "Host": cfg.host,
                    }
                });
            }

            outbounds.push(outbound);
        } else {
            outbounds.push(json!({
                "type": "direct",
                "tag": tag,
                "server": r.ip.to_string(),
                "server_port": r.port,
            }));
        }
    }

    serde_json::to_string_pretty(&json!({ "outbounds": outbounds })).unwrap_or_default()
}

fn generate_clash(results: &[ProbeResult], proxy_cfg: Option<&ProxyConfig>) -> String {
    let proxies: Vec<serde_json::Value> = results
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let name = format!("CF-{}-{}", r.colo.as_deref().unwrap_or("EDGE"), idx + 1);
            let Some(cfg) = proxy_cfg else {
                return json!({
                    "name": name,
                    "type": "socks5",
                    "server": r.ip.to_string(),
                    "port": r.port,
                });
            };
            let mut p = json!({
                "name": name,
                "type": cfg.protocol,
                "server": r.ip.to_string(),
                "port": r.port,
            });
            match cfg.protocol.as_str() {
                "vless" => p["uuid"] = json!(cfg.id_or_password),
                "vmess" => {
                    p["uuid"] = json!(cfg.id_or_password);
                    p["alterId"] = json!(0);
                    p["cipher"] = json!("auto");
                }
                "trojan" => p["password"] = json!(cfg.id_or_password),
                _ => {}
            }
            if cfg.security == "tls" {
                p["tls"] = json!(true);
                p["servername"] = json!(cfg.sni);
                if cfg.protocol == "trojan" {
                    p["sni"] = json!(cfg.sni);
                }
                p["skip-cert-verify"] = json!(false);
            }
            if cfg.transport == "ws" {
                p["network"] = json!("ws");
                p["ws-opts"] = json!({
                    "path": cfg.path,
                    "headers": { "Host": cfg.host },
                });
            }
            p
        })
        .collect();

    // Serialised through serde so values containing quotes, colons or
    // newlines (all legal in a proxy path or remark) cannot break or inject
    // into the YAML document.
    serde_yaml::to_string(&json!({ "proxies": proxies })).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProbeMode, ResultFlags};

    #[test]
    fn clash_yaml_escapes_hostile_values() {
        let mut cfg = ProxyConfig::parse(
            "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&security=tls&path=%2Fws",
        )
        .unwrap();
        cfg.path = "/ws\"\n  injected: true".to_string();
        let r = ProbeResult {
            ip: "104.16.1.1".parse().unwrap(),
            port: 443,
            mode: ProbeMode::Http,
            latencies_ms: vec![10.0],
            flags: ResultFlags::HTTP_OK,
            http_status: 200,
            colo: Some("FRA".into()),
            throughput_mbps: 0.0,
            isp: None,
            asn: None,
        };
        let yaml = generate_clash(&[r], Some(&cfg));
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"][0];
        assert_eq!(proxy["ws-opts"]["path"].as_str(), Some(cfg.path.as_str()));
        assert!(proxy.get("injected").is_none());
        assert_eq!(proxy["port"].as_u64(), Some(443));
    }
}
