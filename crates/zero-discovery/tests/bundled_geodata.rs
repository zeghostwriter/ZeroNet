//! The Android app ships trimmed geosite/geoip files (`assets/geo/`, made by
//! `ZeroNet-Mobile/tools/trim-geodata.py`) so routing rules work from the first launch,
//! offline. This pins that they decode and cover every `geosite:`/`geoip:`
//! tag the app's own config can emit, so a new rule cannot silently point
//! at a tag the bundle lacks.

use serde_json::json;
use zero_config::routing::{DomainPattern, IpPattern};
use zero_router::{DomainMatcher, GeoData, IpMatcher, Router};

fn bundled() -> GeoData {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ZeroNet-Mobile/app/src/main/assets/geo"
    );
    let geosite = std::fs::read(format!("{dir}/geosite.dat")).expect("bundled geosite.dat");
    let geoip = std::fs::read(format!("{dir}/geoip.dat")).expect("bundled geoip.dat");
    GeoData::from_xray_bytes(&geosite, &geoip).expect("bundled geodata decodes")
}

const SS: &str = "ss://YWVzLTEyOC1nY206cGFzcw@203.0.113.10:8388#n";

#[test]
fn every_geo_rule_the_app_emits_resolves_against_the_bundle() {
    let geodata = bundled();
    // Every option that adds a geo rule switched on.
    let config = zero_discovery::build_config(&json!({
        "links": [SS],
        "mode": "vpn",
        "iran_direct": true,
        "block_ads": true,
    }))
    .expect("config builds");
    let text = config.to_string();
    assert!(
        text.contains("geosite:category-ir") && text.contains("geoip:ir"),
        "{text}"
    );
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config compiles");
    // Without geodata (the phone's bug) these same rules go unresolved.
    let empty = Router::build_with_geodata(&generation.config, &GeoData::default());
    assert!(
        !empty.unresolved.is_empty(),
        "the check below would prove nothing"
    );
    let router = Router::build_with_geodata(&generation.config, &geodata);
    assert!(
        router.unresolved.is_empty(),
        "rules the bundle cannot resolve: {:?}",
        router.unresolved
    );
}

#[test]
fn the_bundle_matches_real_iranian_and_ad_destinations() {
    let geodata = bundled();
    let ir = DomainMatcher::build_with_geodata(
        &[DomainPattern::Geosite("category-ir".into())],
        &geodata,
    );
    assert!(ir.matches("www.digikala.com"));
    assert!(!ir.matches("www.google.com"));
    let ads = DomainMatcher::build_with_geodata(
        &[DomainPattern::Geosite("category-ads-all".into())],
        &geodata,
    );
    assert!(ads.matches("ad.doubleclick.net"));
    let private = IpMatcher::build_with_geodata(&[IpPattern::Geoip("private".into())], &geodata);
    assert!(private.matches("192.168.1.1".parse().unwrap()));
    let iran = IpMatcher::build_with_geodata(&[IpPattern::Geoip("ir".into())], &geodata);
    assert!(!iran.matches("8.8.8.8".parse().unwrap()));
    assert!(geodata
        .geoip
        .get("ir")
        .is_some_and(|cidrs| cidrs.len() > 100));
}

/// The whole Android path: the app's asset directory holding the bundled
/// files, the config the app builds for it, and the runtime that loads it.
#[tokio::test]
async fn the_runtime_loads_the_bundle_and_does_not_fetch_over_it() {
    let dir = std::env::temp_dir().join(format!("zray-bundled-geo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ZeroNet-Mobile/app/src/main/assets/geo"
    );
    for name in ["geosite.dat", "geoip.dat"] {
        std::fs::copy(format!("{bundle}/{name}"), dir.join(name)).unwrap();
    }
    let before: Vec<_> = ["geosite.dat", "geoip.dat"]
        .iter()
        .map(|name| std::fs::read(dir.join(name)).unwrap())
        .collect();

    let ports = two_free_ports();
    let config = zero_discovery::build_config_with_assets(
        &json!({"links": [SS], "mode": "proxy", "iran_direct": true, "block_ads": true, "socks_port": ports.0, "http_port": ports.1}),
        Some(&dir),
    )
    .expect("config builds");
    assert_eq!(config["assets"]["autoUpdate"], json!(false));
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = std::sync::Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: std::sync::Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let snapshot = server.asset_snapshot();
    assert_eq!(snapshot["geositeTags"], json!(2), "{snapshot}");
    assert_eq!(snapshot["geoipTags"], json!(2), "{snapshot}");

    // Running, the refresh task must leave the bundle alone: no download
    // attempt is recorded and the files are byte-identical.
    let running = std::sync::Arc::clone(&server);
    let task = tokio::spawn(async move {
        let _ = running.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    task.abort();
    assert_eq!(server.asset_snapshot()["files"], json!([]), "a refresh ran");
    for (name, bytes) in ["geosite.dat", "geoip.dat"].iter().zip(&before) {
        assert_eq!(
            &std::fs::read(dir.join(name)).unwrap(),
            bytes,
            "{name} was replaced"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two distinct free ports, held together so they cannot coincide.
fn two_free_ports() -> (u16, u16) {
    let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    )
}
