//! A live check of the MASQUE tunnel against Cloudflare's real edge.
//!
//! Ignored by default: it needs a WARP account that was enrolled for MASQUE
//! (a usque-style file with `ec_private` and the enrollment reply under
//! `masque`) and a network that reaches the edge. Run it with
//!
//! ```text
//! ZRAY_WARP_TEST_ACCOUNT=/path/to/account.json \
//!   cargo test -p zero-runtime --test warp_live -- --ignored --nocapture
//! ```
//!
//! `ZRAY_WARP_TEST_ROUTE` picks `masque-h2` (default) or `masque-h3`. The
//! request goes to `www.cloudflare.com/cdn-cgi/trace` (the name is resolved
//! inside the tunnel), which says `warp=on` only when it arrived through WARP.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_config::{OutboundProtocol, WarpRoute};
use zero_core::Address;

fn account() -> Option<(serde_json::Value, WarpRoute)> {
    let path = std::env::var("ZRAY_WARP_TEST_ACCOUNT").ok()?;
    let value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let route = std::env::var("ZRAY_WARP_TEST_ROUTE")
        .ok()
        .and_then(|name| WarpRoute::parse(&name))
        .unwrap_or(WarpRoute::MasqueHttp2);
    Some((value, route))
}

#[tokio::test]
#[ignore = "needs a MASQUE-enrolled WARP account and a network that reaches Cloudflare"]
async fn a_masque_tunnel_carries_a_request_through_warp() {
    let Some((account, route)) = account() else {
        eprintln!("ZRAY_WARP_TEST_ACCOUNT is not set; nothing to check");
        return;
    };
    let masque = &account["masque"]["config"];
    let addresses: Vec<&str> = ["v4", "v6"]
        .iter()
        .filter_map(|family| masque["interface"]["addresses"][family].as_str())
        .collect();
    let settings = serde_json::json!({
        "route": route.name(),
        "masque": {
            "privateKey": account["ec_private"],
            "serverPublicKey": masque["peers"][0]["public_key"],
            "address": addresses,
        }
    });
    let outbound = zero_config::xray_json::parse_config(&serde_json::json!({
        "outbounds": [{"protocol": "warp", "tag": "warp", "settings": settings}]
    }))
    .expect("the account parses")
    .0
    .outbounds[0]
        .clone();
    let OutboundProtocol::AmneziaWireguard(config) = outbound.protocol else {
        panic!("expected a WARP outbound");
    };

    let started = std::time::Instant::now();
    let stack = zero_runtime::warp::tunnel(&config, None)
        .await
        .expect("the tunnel comes up");
    eprintln!("tunnel up in {} ms", started.elapsed().as_millis());

    let mut stream = tokio::time::timeout(
        Duration::from_secs(15),
        stack.connect_host(&Address::parse_host("www.cloudflare.com"), 80),
    )
    .await
    .expect("connect in time")
    .expect("TCP through the tunnel");
    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut body))
        .await
        .expect("a response in time")
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    // Only the fields that show the path, not the caller's address.
    for line in text
        .lines()
        .filter(|l| l.starts_with("warp=") || l.starts_with("colo="))
    {
        eprintln!("{line}");
    }
    let head: String = text
        .lines()
        .filter(|line| !line.starts_with("ip=") && !line.starts_with("loc="))
        .take(14)
        .collect::<Vec<_>>()
        .join(" | ");
    eprintln!("{} bytes: {head}", body.len());
    assert!(
        text.contains("warp=on"),
        "the request did not go through WARP"
    );
}

/// How fast a bulk download goes through the tunnel. Prints the rate; asserts
/// only that the whole file arrived.
#[tokio::test]
#[ignore = "needs a MASQUE-enrolled WARP account and a network that reaches Cloudflare"]
async fn a_bulk_download_goes_through_the_tunnel() {
    let Some((account, route)) = account() else {
        return;
    };
    let masque = &account["masque"]["config"];
    let addresses: Vec<&str> = ["v4", "v6"]
        .iter()
        .filter_map(|family| masque["interface"]["addresses"][family].as_str())
        .collect();
    let value = serde_json::json!({"outbounds": [{"protocol": "warp", "tag": "warp", "settings": {
        "route": route.name(),
        "masque": {
            "privateKey": account["ec_private"],
            "serverPublicKey": masque["peers"][0]["public_key"],
            "address": addresses,
        }
    }}]});
    let outbound = zero_config::xray_json::parse_config(&value)
        .unwrap()
        .0
        .outbounds[0]
        .clone();
    let OutboundProtocol::AmneziaWireguard(config) = outbound.protocol else {
        panic!("expected a WARP outbound");
    };
    let stack = zero_runtime::warp::tunnel(&config, None).await.unwrap();
    let mut stream = stack
        .connect_host(&Address::parse_host("speedtest.tele2.net"), 80)
        .await
        .expect("TCP through the tunnel");
    stream
        .write_all(
            b"GET /10MB.zip HTTP/1.1\r\nHost: speedtest.tele2.net\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut total = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(20), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total += n,
            Ok(Err(error)) => panic!("read: {error}"),
            Err(_) => panic!("stalled after {total} bytes"),
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    eprintln!(
        "{total} bytes in {seconds:.2} s = {:.2} Mbit/s",
        total as f64 * 8.0 / seconds / 1e6
    );
    assert!(total >= 10 * 1024 * 1024, "only {total} bytes arrived");
}

/// Which WireGuard endpoint and junk settings get a WARP handshake through on
/// this network. Prints one line per attempt; asserts nothing, since the
/// answer is the point. Needs `ZRAY_WARP_TEST_WG`, a file with the account's
/// registration reply under `register` and its private key under `wg_private`.
#[tokio::test]
#[ignore = "needs a WireGuard WARP account and a network that reaches Cloudflare"]
async fn which_wireguard_settings_get_through() {
    let Some(path) = std::env::var_os("ZRAY_WARP_TEST_WG") else {
        return;
    };
    let file: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let config = &file["register"]["config"];
    let extra: Vec<String> = std::env::var("ZRAY_WARP_TEST_ENDPOINTS")
        .map(|list| list.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let mut endpoints: Vec<String> = [
        "162.159.192.1:2408",
        "162.159.192.1:500",
        "162.159.192.1:4500",
        "162.159.193.1:2408",
        "188.114.97.1:2408",
        "188.114.98.1:2408",
    ]
    .iter()
    .map(|e| e.to_string())
    .collect();
    endpoints.extend(extra);
    let junk: [(u16, u16, u16); 4] = [(0, 0, 0), (4, 40, 70), (5, 50, 100), (8, 50, 1000)];
    for endpoint in &endpoints {
        for (jc, jmin, jmax) in junk {
            let settings = serde_json::json!({
                "route": "wireguard",
                "wireguard": {
                    "privateKey": file["wg_private"],
                    "peerPublicKey": config["peers"][0]["public_key"],
                    "endpoint": endpoint,
                    "address": config["interface"]["addresses"]["v4"],
                    "reserved": config["client_id"],
                    "persistentKeepalive": 25,
                    "amnezia": {"jc": jc, "jmin": jmin, "jmax": jmax},
                }
            });
            let parsed = zero_config::xray_json::parse_config(&serde_json::json!({
                "outbounds": [{"protocol": "warp", "tag": "warp", "settings": settings}]
            }));
            let Ok((parsed, _)) = parsed else {
                eprintln!("{endpoint} jc={jc}: config error");
                continue;
            };
            let OutboundProtocol::AmneziaWireguard(wg) = parsed.outbounds[0].protocol.clone()
            else {
                continue;
            };
            let peer: std::net::SocketAddr = endpoint.parse().unwrap();
            let started = std::time::Instant::now();
            let stack = zero_protocol::wg_stack::shared(
                peer,
                zero_runtime::outbound::wireguard_stack_params(&wg),
            )
            .unwrap();
            let answer =
                tokio::time::timeout(Duration::from_secs(7), stack.resolve("cloudflare.com")).await;
            let verdict = match answer {
                Ok(Ok(_)) => format!("OK in {} ms", started.elapsed().as_millis()),
                Ok(Err(error)) => format!("error {error}"),
                Err(_) => "no answer".into(),
            };
            eprintln!("{endpoint} jc={jc} jmin={jmin} jmax={jmax}: {verdict}");
        }
    }
}

/// The hybrid outbound on the real network: WireGuard from one account and
/// MASQUE from another (the test files hold one each), all three routes
/// raced. Prints which won and how long it took, then sends a request
/// through the winner.
#[tokio::test]
#[ignore = "needs both test account files and a network that reaches Cloudflare"]
async fn the_hybrid_race_picks_a_working_route() {
    let (Some(masque_path), Some(wg_path)) = (
        std::env::var_os("ZRAY_WARP_TEST_ACCOUNT"),
        std::env::var_os("ZRAY_WARP_TEST_WG"),
    ) else {
        return;
    };
    let masque_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(masque_path).unwrap()).unwrap();
    let wg_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(wg_path).unwrap()).unwrap();
    let masque = &masque_file["masque"]["config"];
    let wg = &wg_file["register"]["config"];
    let settings = serde_json::json!({
        "route": "auto",
        "wireguard": {
            "privateKey": wg_file["wg_private"],
            "peerPublicKey": wg["peers"][0]["public_key"],
            "endpoint": "162.159.192.1:2408",
            "address": wg["interface"]["addresses"]["v4"],
            "reserved": wg["client_id"],
            "persistentKeepalive": 25,
        },
        "masque": {
            "privateKey": masque_file["ec_private"],
            "serverPublicKey": masque["peers"][0]["public_key"],
            "address": [masque["interface"]["addresses"]["v4"]],
        }
    });
    let parsed = zero_config::xray_json::parse_config(&serde_json::json!({
        "outbounds": [{"protocol": "warp", "tag": "warp", "settings": settings}]
    }))
    .unwrap()
    .0;
    let OutboundProtocol::AmneziaWireguard(config) = parsed.outbounds[0].protocol.clone() else {
        panic!("expected a WARP outbound");
    };
    let started = std::time::Instant::now();
    let tunnel = zero_runtime::warp::tunnel(&config, Some("162.159.192.1:2408".parse().unwrap()))
        .await
        .expect("a route comes up");
    eprintln!(
        "winner: {} after {} ms",
        tunnel.route().name(),
        started.elapsed().as_millis()
    );
    let mut stream = tunnel
        .connect_host(&Address::parse_host("www.cloudflare.com"), 80)
        .await
        .expect("TCP through the tunnel");
    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("warp=on"));
}

/// The WireGuard route alone: a request through it, printing how the response
/// arrives. `ZRAY_WARP_TEST_WG` names the file; `ZRAY_WARP_TEST_ENDPOINT`
/// (default 162.159.192.1:2408) the peer.
#[tokio::test]
#[ignore = "needs a WireGuard WARP account and a network that reaches Cloudflare"]
async fn a_wireguard_route_carries_a_request() {
    let Some(path) = std::env::var_os("ZRAY_WARP_TEST_WG") else {
        return;
    };
    let file: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let config = &file["register"]["config"];
    let endpoint =
        std::env::var("ZRAY_WARP_TEST_ENDPOINT").unwrap_or_else(|_| "162.159.192.1:2408".into());
    let host = std::env::var("ZRAY_WARP_TEST_HOST").unwrap_or_else(|_| "www.cloudflare.com".into());
    let junk: u16 = std::env::var("ZRAY_WARP_TEST_JUNK")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let parsed = zero_config::xray_json::parse_config(&serde_json::json!({
        "outbounds": [{"protocol": "warp", "tag": "warp", "settings": {
            "route": "wireguard",
            "wireguard": {
                "privateKey": file["wg_private"],
                "peerPublicKey": config["peers"][0]["public_key"],
                "endpoint": endpoint,
                "address": config["interface"]["addresses"]["v4"],
                "reserved": config["client_id"],
                "persistentKeepalive": 25,
                "amnezia": {"jc": junk, "jmin": 40, "jmax": 70},
            }
        }}]
    }))
    .unwrap()
    .0;
    let OutboundProtocol::AmneziaWireguard(wg) = parsed.outbounds[0].protocol.clone() else {
        panic!("expected a WARP outbound");
    };
    let tunnel = zero_runtime::warp::tunnel(&wg, Some(endpoint.parse().unwrap()))
        .await
        .expect("the tunnel");
    let started = std::time::Instant::now();
    let mut stream = tunnel
        .connect_host(&Address::parse_host(&host), 80)
        .await
        .expect("TCP connect");
    eprintln!("connected in {} ms", started.elapsed().as_millis());
    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut total = 0usize;
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(8), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                eprintln!(
                    "closed after {total} bytes, {} ms",
                    started.elapsed().as_millis()
                );
                break;
            }
            Ok(Ok(n)) => {
                total += n;
                eprintln!("+{n} bytes at {} ms", started.elapsed().as_millis());
            }
            Ok(Err(error)) => panic!("read error after {total} bytes: {error}"),
            Err(_) => panic!("nothing more after {total} bytes"),
        }
    }
    assert!(total > 0);
}

/// Which edge addresses next to the configured ones accept a MASQUE tunnel
/// over HTTP/2 from here. Prints one line per address that does.
#[tokio::test]
#[ignore = "needs a MASQUE-enrolled WARP account and a network that reaches Cloudflare"]
async fn which_edge_addresses_take_a_masque_tunnel() {
    let Some((account, _)) = account() else {
        return;
    };
    let masque = &account["masque"]["config"];
    let parsed = zero_config::xray_json::parse_config(&serde_json::json!({
        "outbounds": [{"protocol": "warp", "tag": "warp", "settings": {
            "route": "masque-h2",
            "masque": {
                "privateKey": account["ec_private"],
                "serverPublicKey": masque["peers"][0]["public_key"],
                "address": [masque["interface"]["addresses"]["v4"]],
            }
        }}]
    }))
    .unwrap()
    .0;
    let OutboundProtocol::AmneziaWireguard(config) = parsed.outbounds[0].protocol.clone() else {
        panic!("expected a WARP outbound");
    };
    let found = zero_runtime::warp::scan_endpoints(
        config.masque.as_deref().unwrap(),
        254,
        254,
        Duration::from_secs(90),
    )
    .await;
    for (address, took) in &found {
        eprintln!("{address} {} ms", took.as_millis());
    }
    eprintln!("{} addresses answered", found.len());
    assert!(!found.is_empty(), "no address answered");
}

// ------------------------------------------------------------- hybrid order
//
// The `hybrid` order against the real service: Cloudflare's tunnel brought up
// through a server, then a request through the tunnel.
//
// ```text
// ZRAY_WARP_TEST_ACCOUNT=/path/to/account.json \
// ZRAY_WARP_TEST_CARRIER='vless://…@host:443?security=tls&sni=…#carrier' \
//   cargo test -p zero-runtime --test warp_live -- --ignored --nocapture carried
// ```

#[tokio::test]
#[ignore = "needs a MASQUE-enrolled WARP account and a server that reaches Cloudflare"]
async fn a_carried_tunnel_reaches_warp_through_a_server() {
    let (Some((file, _)), Ok(carrier)) = (account(), std::env::var("ZRAY_WARP_TEST_CARRIER"))
    else {
        eprintln!("ZRAY_WARP_TEST_ACCOUNT or ZRAY_WARP_TEST_CARRIER is not set; nothing to check");
        return;
    };
    let masque = &file["masque"]["config"];
    let addresses: Vec<&str> = ["v4", "v6"]
        .iter()
        .filter_map(|family| masque["interface"]["addresses"][family].as_str())
        .collect();
    let settings = serde_json::json!({
        "route": "masque-h2",
        "mode": "hybrid",
        "exits": [carrier],
        "masque": {
            "privateKey": file["ec_private"],
            "serverPublicKey": masque["peers"][0]["public_key"],
            "address": addresses,
        }
    });
    let outbound = zero_config::xray_json::parse_config(&serde_json::json!({
        "outbounds": [{"protocol": "warp", "tag": "warp", "settings": settings}]
    }))
    .expect("the account parses")
    .0
    .outbounds[0]
        .clone();
    let OutboundProtocol::AmneziaWireguard(config) = outbound.protocol else {
        panic!("expected a WARP outbound");
    };
    let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());
    let started = std::time::Instant::now();
    let tunnel = zero_runtime::warp::tunnel_for(&config, None, Some(&resolver))
        .await
        .expect("the tunnel comes up");
    assert!(
        tunnel.carried(),
        "the tunnel was dialled directly, not through the server"
    );
    eprintln!("carried tunnel up in {} ms", started.elapsed().as_millis());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(15),
        tunnel.connect_host(&Address::parse_host("www.cloudflare.com"), 80),
    )
    .await
    .expect("connect in time")
    .expect("TCP through the tunnel");
    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut reply)).await;
    let reply = String::from_utf8_lossy(&reply);
    eprintln!("{reply}");
    assert!(
        reply.contains("warp=on"),
        "the request did not arrive through WARP"
    );
}
