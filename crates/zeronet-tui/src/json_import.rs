//! Telling a pasted or opened JSON config from other text, and what is in it.
//!
//! People hand over configs as Xray JSON: one config object, or an array of
//! them (a panel's JSON subscription, where each carries a `remarks` name), in
//! a pasted block or a `.json` file. A file also arrives as a *path*: dragging
//! it onto a terminal pastes its location, often quoted or escaped.
//!
//! This module only reads: [`profiles_from_json`] says which configs a text
//! holds and where each one's server is (so the node list can show it and the
//! ping can reach it), and [`pasted_file_path`] says whether a paste is the
//! path of a file that exists. Storing them is the app's job.

use std::path::PathBuf;

/// One config found in a JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonProfile {
    /// The config, pretty-printed, as it will be stored and run.
    pub json: String,
    /// The name it came with (`remarks`), or one made from its server.
    pub remark: String,
    /// The protocol of its proxy outbound (`vless`, `trojan`...).
    pub protocol: String,
    /// Where that outbound's server is, so the list can show and ping it.
    pub address: String,
    pub port: u16,
}

/// The configs in `text`, or why it is not a set of them.
///
/// `Err` means the text is not JSON at all, or holds no config; each entry of
/// the `Ok` list is either a profile or the reason that one entry (of an
/// array) could not be read, so one bad entry does not hide the others.
pub fn profiles_from_json(text: &str) -> Result<Vec<Result<JsonProfile, String>>, String> {
    // Windows editors save UTF-8 with a byte-order mark.
    let text = text.trim_start_matches('\u{feff}').trim();
    if !(text.starts_with('{') || text.starts_with('[')) {
        return Err("not JSON".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("not valid JSON: {error}"))?;
    let entries: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        object @ serde_json::Value::Object(_) => vec![object],
        _ => return Err("not a config".into()),
    };
    let profiles: Vec<_> = entries
        .iter()
        .filter(|entry| entry.get("outbounds").is_some_and(|o| o.is_array()))
        .map(profile_of)
        .collect();
    if profiles.is_empty() {
        return Err("JSON, but no config with `outbounds` in it".into());
    }
    Ok(profiles)
}

fn profile_of(config: &serde_json::Value) -> Result<JsonProfile, String> {
    let (parsed, _) = zero_config::parse_config(config)?;
    // The outbound a config exists for: the one tagged `proxy`, else the
    // first that is not one of the helpers every config carries.
    let proxy = parsed
        .outbounds
        .iter()
        .find(|outbound| &*outbound.tag == "proxy")
        .or_else(|| {
            parsed.outbounds.iter().find(|outbound| {
                !matches!(
                    outbound.protocol,
                    zero_config::OutboundProtocol::Freedom { .. }
                        | zero_config::OutboundProtocol::Blackhole { .. }
                        | zero_config::OutboundProtocol::Dns { .. }
                )
            })
        })
        .or_else(|| parsed.outbounds.first())
        .ok_or_else(|| "the config has no outbound".to_string())?;
    let protocol = proxy.protocol.name().to_string();
    let (address, port) = proxy
        .endpoint()
        .map_or(("proxy".to_string(), 443), |(address, port)| {
            (address.host_string(), port)
        });
    let named = ["remarks", "remark", "ps", "name"].iter().find_map(|key| {
        config
            .get(*key)
            .and_then(|name| name.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
    });
    let remark = named.map_or_else(
        || {
            if address == "proxy" {
                format!("{}-Node", protocol.to_uppercase())
            } else {
                format!("{} {address}", protocol.to_uppercase())
            }
        },
        str::to_string,
    );
    Ok(JsonProfile {
        json: serde_json::to_string_pretty(config).map_err(|error| error.to_string())?,
        remark,
        protocol,
        address,
        port,
    })
}

/// The file a pasted line names, if it is one that exists.
///
/// A terminal pastes a dropped file as its path, in whichever form the shell
/// would take it: bare, in quotes, with spaces escaped by backslashes, as a
/// `file://` URL with percent-escapes, or starting with `~`. Anything with
/// more than one line, or longer than any path, is not a path.
pub fn pasted_file_path(text: &str) -> Option<PathBuf> {
    let line = text.trim();
    if line.is_empty() || line.contains('\n') || line.len() > 4096 {
        return None;
    }
    let unquoted = line
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            line.strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .unwrap_or(line);
    let decoded = match unquoted.strip_prefix("file://") {
        Some(url) => percent_decode(url.strip_prefix("localhost").unwrap_or(url))?,
        None => unescape_spaces(unquoted),
    };
    // A Windows drive path in a `file:///C:/…` URL keeps no leading slash.
    let decoded = match decoded.as_bytes() {
        [b'/', letter, b':', ..] if letter.is_ascii_alphabetic() => decoded[1..].to_string(),
        _ => decoded,
    };
    let expanded = match decoded.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| PathBuf::from(home).join(rest))?,
        None => PathBuf::from(decoded),
    };
    std::fs::metadata(&expanded)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|_| expanded)
}

fn unescape_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        // A backslash before a space (or another backslash) is a shell
        // escape; anywhere else it is a Windows path separator.
        if c == '\\' && matches!(chars.peek(), Some(' ' | '\\' | '(' | ')' | '\'')) {
            out.extend(chars.next());
        } else {
            out.push(c);
        }
    }
    out
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

    fn vless(remarks: Option<&str>, address: &str) -> serde_json::Value {
        let mut config = serde_json::json!({
            "inbounds": [],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "proxy", "protocol": "vless",
                 "settings": {"address": address, "port": 8443, "id": UUID, "encryption": "none"},
                 "streamSettings": {"network": "raw", "security": "tls",
                                    "tlsSettings": {"serverName": "front.example"}}}
            ]
        });
        if let Some(remarks) = remarks {
            config["remarks"] = remarks.into();
        }
        config
    }

    #[test]
    fn a_config_is_read_with_its_server_and_name() {
        let text = vless(Some("My server"), "198.51.100.7").to_string();
        let profiles = profiles_from_json(&text).unwrap();
        let profile = profiles[0].as_ref().unwrap();
        assert_eq!(profile.remark, "My server");
        assert_eq!(profile.protocol, "vless");
        assert_eq!(
            (profile.address.as_str(), profile.port),
            ("198.51.100.7", 8443)
        );
    }

    #[test]
    fn an_unnamed_config_is_named_after_its_server() {
        let text = vless(None, "s.example").to_string();
        let profile = profiles_from_json(&text).unwrap().remove(0).unwrap();
        assert_eq!(profile.remark, "VLESS s.example");
    }

    #[test]
    fn an_array_gives_one_profile_each_and_a_bad_one_does_not_hide_the_rest() {
        let broken = serde_json::json!({"outbounds": [{"protocol": "vless", "settings": {}}]});
        let text = serde_json::json!([
            vless(Some("a"), "1.1.1.1"),
            broken,
            vless(Some("c"), "3.3.3.3"),
            {"not": "a config"},
        ])
        .to_string();
        let profiles = profiles_from_json(&text).unwrap();
        assert_eq!(
            profiles.len(),
            3,
            "the entry with no outbounds is not a config"
        );
        assert_eq!(profiles[0].as_ref().unwrap().remark, "a");
        assert!(profiles[1].is_err());
        assert_eq!(profiles[2].as_ref().unwrap().remark, "c");
    }

    #[test]
    fn a_byte_order_mark_and_surrounding_space_are_ignored() {
        let text = format!("\u{feff}\n  {}\n", vless(Some("bom"), "2.2.2.2"));
        assert!(profiles_from_json(&text).unwrap()[0].is_ok());
    }

    #[test]
    fn text_that_is_not_a_config_is_said_so() {
        assert!(profiles_from_json("vless://x@y:1").is_err());
        assert!(profiles_from_json("{\"a\": 1}").is_err());
        assert!(profiles_from_json("{broken").is_err());
        assert!(profiles_from_json("[1, 2]").is_err());
    }

    #[test]
    fn every_way_a_terminal_pastes_a_path_finds_the_file() {
        let dir = std::env::temp_dir().join(format!("zray-paste-{}", std::process::id()));
        let spaced = dir.join("my configs");
        std::fs::create_dir_all(&spaced).unwrap();
        let file = spaced.join("sub (1).json");
        std::fs::write(&file, "{}").unwrap();
        let plain = file.to_string_lossy().to_string();
        let escaped = plain
            .replace(' ', "\\ ")
            .replace('(', "\\(")
            .replace(')', "\\)");
        let url = format!("file://{}", plain.replace(' ', "%20"));
        for text in [
            plain.clone(),
            format!("\"{plain}\""),
            format!("'{plain}'"),
            escaped,
            url,
            format!("  {plain}\n"),
        ] {
            assert_eq!(
                pasted_file_path(&text).as_deref(),
                Some(file.as_path()),
                "{text}"
            );
        }
        // Not paths: missing files, directories, several lines, config text.
        assert!(pasted_file_path(&format!("{plain}.missing")).is_none());
        assert!(pasted_file_path(&dir.to_string_lossy()).is_none());
        assert!(pasted_file_path(&format!("{plain}\n{plain}")).is_none());
        assert!(pasted_file_path("{\"outbounds\": []}").is_none());
        assert!(pasted_file_path("vless://x@y:443").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
