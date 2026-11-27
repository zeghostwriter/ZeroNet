//! Subscription addresses from self-hosted panels, rewritten to the form that
//! costs the user least.
//!
//! A BPB Worker Panel (bia-pain-bache/BPB-Worker-Panel, `src/worker.ts` and
//! `src/handlers/subscription.ts`) serves every subscription under
//! `/<secret path>/sub/<kind>?app=<client>`. Its `normal` and `fragment` kinds
//! for Xray, sing-box and Clash wrap the same servers in the panel's own
//! fragment, DNS and routing settings — several times the bytes of the
//! servers themselves, all of which ZeroNet discards because it decides those
//! per network by itself. `sub/raw?app=xray` is the same servers (including
//! the panel's chain proxy and custom configs) as a plain base64 link list,
//! so every such address is fetched in that form instead. The panel's own
//! address (`/<secret path>/panel`) carries the same secret, so pasting it
//! works too.
//!
//! WARP kinds are left alone: they carry WireGuard accounts, not the proxies.
//!
//! The secret path is a credential. Nothing here logs or stores it; the
//! rewrite is a pure function of the address the user gave.

use url::Url;

/// The address to fetch for a subscription the user added: the cheapest
/// equivalent when `address` is a known panel's, otherwise `address` as is.
pub fn subscription_fetch_url(address: &str) -> String {
    bpb_raw(address).unwrap_or_else(|| address.to_string())
}

fn bpb_raw(address: &str) -> Option<String> {
    let mut url = Url::parse(address.trim()).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    let segments: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();
    let secret = match segments.as_slice() {
        [secret, "sub", "normal" | "fragment" | "raw", ..] => {
            let client = url
                .query_pairs()
                .find(|(key, _)| key == "app")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default();
            if !matches!(client.as_str(), "" | "xray" | "sing-box" | "clash") {
                return None;
            }
            *secret
        }
        [secret, "panel" | "login"] => *secret,
        _ => return None,
    };
    // BPB's secret path is random text; a short, common word here is some
    // other product's route, not a panel.
    if secret.len() < 8 {
        return None;
    }
    let path = format!("/{secret}/sub/raw");
    url.set_path(&path);
    url.set_query(Some("app=xray"));
    Some(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "Xq3Lm9Pz2Rk7Tw4V";

    #[test]
    fn bpb_json_and_clash_kinds_become_the_raw_link_list() {
        for kind in ["normal", "fragment", "raw"] {
            for app in ["xray", "sing-box", "clash"] {
                let address =
                    format!("https://bpb.example.workers.dev/{SECRET}/sub/{kind}?app={app}");
                assert_eq!(
                    subscription_fetch_url(&address),
                    format!("https://bpb.example.workers.dev/{SECRET}/sub/raw?app=xray"),
                    "{kind} {app}"
                );
            }
        }
    }

    #[test]
    fn the_panel_address_itself_becomes_its_subscription() {
        assert_eq!(
            subscription_fetch_url(&format!("https://panel.example.com/{SECRET}/panel")),
            format!("https://panel.example.com/{SECRET}/sub/raw?app=xray")
        );
    }

    #[test]
    fn a_custom_port_and_the_name_fragment_survive() {
        assert_eq!(
            subscription_fetch_url(&format!(
                "https://1.2.3.4:8443/{SECRET}/sub/normal?app=xray#%F0%9F%92%A6%20BPB"
            )),
            format!("https://1.2.3.4:8443/{SECRET}/sub/raw?app=xray#%F0%9F%92%A6%20BPB")
        );
    }

    #[test]
    fn warp_and_other_addresses_are_left_alone() {
        for address in [
            format!("https://bpb.example.com/{SECRET}/sub/warp?app=xray"),
            format!("https://bpb.example.com/{SECRET}/sub/warp-pro?app=xray-knocker"),
            format!("https://bpb.example.com/{SECRET}/sub/normal?app=wireguard"),
            "https://raw.githubusercontent.com/a/b/main/sub.txt".to_string(),
            "https://marzban.example.com/sub/abcdef0123456789".to_string(),
            "https://host.example.com/api/panel".to_string(),
            "ftp://host.example.com/Xq3Lm9Pz2Rk7Tw4V/panel".to_string(),
            "not a url".to_string(),
        ] {
            assert_eq!(subscription_fetch_url(&address), address);
        }
    }

    /// A body shaped exactly like BPB's `getURLConfigs` (src/cores/common.ts):
    /// base64 of VLESS and Trojan over WebSocket+TLS with `?ed=2560` early
    /// data in the path, a clean-IP address, plus a chain proxy.
    #[test]
    fn a_bpb_raw_body_parses_into_usable_links() {
        use base64::Engine as _;
        let list = "vless://00000000-0000-4000-8000-000000000001@104.16.1.2:443?encryption=none&host=bpb.example.workers.dev&type=ws&security=tls&path=%2FaBcD%3Fed%3D2560&sni=bpb.example.workers.dev&fp=chrome&alpn=http%2F1.1#%F0%9F%92%A6%201%20-%20VL\n\
trojan://secret-pass@bpb.example.workers.dev:2053?host=bpb.example.workers.dev&type=ws&security=tls&path=%2FeFgH%3Fed%3D2560&sni=bpb.example.workers.dev&fp=randomized&alpn=http%2F1.1#%F0%9F%92%A6%202%20-%20TR\n\
vless://00000000-0000-4000-8000-000000000002@chain.example.net:443?encryption=none&security=reality&sni=www.speedtest.net&fp=chrome&pbk=rN3cEWuB4KGvVwZ1cTu6tS8m9p6r7ZC3o0B1qYq2Q0E&sid=ab&type=tcp#%F0%9F%92%A6%20Chain%20proxy%20%F0%9F%94%97\n";
        let body = base64::engine::general_purpose::STANDARD.encode(list);
        let report = crate::parse_links(&body);
        assert_eq!(report.rejected, 0, "{:?}", report.reasons);
        assert_eq!(report.items.len(), 3);
    }
}
