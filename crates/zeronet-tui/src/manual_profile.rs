//! Manual Profile Creator Form with live field editing.

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const PROTOCOLS: [&str; 4] = ["vless", "trojan", "shadowsocks", "vmess"];
pub const SECURITIES: [&str; 3] = ["reality", "tls", "none"];
pub const TRANSPORTS: [&str; 4] = ["tcp", "ws", "grpc", "xhttp"];
pub const FLOWS: [&str; 2] = ["xtls-rprx-vision", "none"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualProfileForm {
    pub remark: String,
    pub protocol_idx: usize,
    pub address: String,
    pub port: u16,
    pub uuid_or_password: String,
    pub security_idx: usize,
    pub sni: String,
    pub pbk: String,
    pub sid: String,
    pub flow_idx: usize,
    pub transport_idx: usize,
    pub ws_path: String,
    pub focused_field: usize,
}

impl Default for ManualProfileForm {
    fn default() -> Self {
        Self {
            remark: "My Custom Node".into(),
            protocol_idx: 0, // vless
            address: "155.117.13.26".into(),
            port: 443,
            uuid_or_password: "245abd35-7efa-4bc8-85d4-a04f3798329f".into(),
            security_idx: 0, // reality
            sni: "www.googletagmanager.com".into(),
            pbk: "F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY".into(),
            sid: "7963d08380d47375".into(),
            flow_idx: 0,      // vision
            transport_idx: 0, // tcp
            ws_path: "/".into(),
            focused_field: 0,
        }
    }
}

impl ManualProfileForm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field_count() -> usize {
        12
    }

    /// Whether the focused field takes free text rather than cycling through
    /// a fixed set of values.
    ///
    /// Drives the key router: on a text field printable keys are literal, on
    /// a cycler Space and the arrows change the value.
    pub fn focused_field_is_text(&self) -> bool {
        !matches!(self.focused_field, 1 | 5 | 9 | 10)
    }

    /// Indices of the fields that cycle through fixed options.
    pub const CYCLER_FIELDS: [usize; 4] = [1, 5, 9, 10];

    pub fn to_json(&self) -> Result<String> {
        let proto = PROTOCOLS[self.protocol_idx % PROTOCOLS.len()];
        let sec = SECURITIES[self.security_idx % SECURITIES.len()];
        let trans = TRANSPORTS[self.transport_idx % TRANSPORTS.len()];
        let flow = if self.flow_idx == 0 {
            "xtls-rprx-vision"
        } else {
            ""
        };

        let mut outbound = serde_json::json!({
            "tag": "proxy",
            "protocol": proto,
            "streamSettings": {
                "network": trans,
                "security": sec,
            }
        });

        if proto == "vless" {
            outbound["settings"] = serde_json::json!({
                "vnext": [{
                    "address": self.address,
                    "port": self.port,
                    "users": [{
                        "id": self.uuid_or_password,
                        "flow": flow,
                        "encryption": "none"
                    }]
                }]
            });
        } else if proto == "trojan" {
            outbound["settings"] = serde_json::json!({
                "servers": [{
                    "address": self.address,
                    "port": self.port,
                    "password": self.uuid_or_password
                }]
            });
        } else if proto == "shadowsocks" {
            outbound["settings"] = serde_json::json!({
                "servers": [{
                    "address": self.address,
                    "port": self.port,
                    "method": "chacha20-ietf-poly1305",
                    "password": self.uuid_or_password
                }]
            });
        } else {
            outbound["settings"] = serde_json::json!({
                "vnext": [{
                    "address": self.address,
                    "port": self.port,
                    "users": [{
                        "id": self.uuid_or_password,
                        "security": "auto"
                    }]
                }]
            });
        }

        if sec == "reality" {
            outbound["streamSettings"]["realitySettings"] = serde_json::json!({
                "serverName": self.sni,
                "publicKey": self.pbk,
                "shortId": self.sid,
                "fingerprint": "chrome"
            });
        } else if sec == "tls" {
            outbound["streamSettings"]["tlsSettings"] = serde_json::json!({
                "serverName": self.sni
            });
        }

        if trans == "ws" {
            outbound["streamSettings"]["wsSettings"] = serde_json::json!({
                "path": self.ws_path
            });
        }

        let full_config = serde_json::json!({
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks"
            }, {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http"
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ]
        });

        Ok(serde_json::to_string_pretty(&full_config)?)
    }
}
