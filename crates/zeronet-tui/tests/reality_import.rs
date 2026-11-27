//! Import shapes for VLESS REALITY profiles, end to end through the client's
//! own preparation path.
//!
//! REALITY is the one security whose mistakes are silent: a profile that
//! merely *looks* right — a missing ClientHello shape, a dropped `spx`, a
//! `realitySettings` block whose fields the client stops carrying — still
//! starts an engine, and the failure only shows up as the server relaying the
//! connection to the decoy site. On the wire that reads as a certificate that
//! does not belong to the tunnel, which is what users report as a
//! "certificate verification error".
//!
//! The profiles here are the shapes people actually paste: a full share link,
//! a link missing the optional parameters, and raw Xray JSON both with and
//! without a fingerprint. Every one of them must come out of
//! [`prepare_runnable_config_with`] still carrying REALITY with its server
//! name, public key, shortId and a ClientHello shape, and must survive
//! [`validate_profile`] — the check that runs before an import is stored.

use zeronet_tui::daemon::{prepare_runnable_config_with, validate_profile, EngineOptions};

const UUID: &str = "245abd35-7efa-4bc8-85d4-a04f3798329f";
/// A 32-byte key in Xray's base64url spelling, as `pbk=` carries it.
const PBK: &str = "F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY";
const SHORT_ID: &str = "ab12cd34";
const SERVER_NAME: &str = "www.speedtest.net";

fn full_link() -> String {
    format!(
        "vless://{UUID}@1.2.3.4:443?security=reality&sni={SERVER_NAME}&fp=chrome&pbk={PBK}\
&sid={SHORT_ID}&spx=%2F&type=tcp&flow=xtls-rprx-vision&encryption=none#Full"
    )
}

fn bare_link() -> String {
    // No `fp`, no `spx`, no `flow`: the shape many providers hand out, and the
    // one most likely to lose REALITY on the way through a config builder.
    format!("vless://{UUID}@1.2.3.4:443?security=reality&sni={SERVER_NAME}&pbk={PBK}&sid={SHORT_ID}&type=tcp#Bare")
}

fn raw_json(fingerprint: bool) -> String {
    let mut reality = serde_json::json!({
        "serverName": SERVER_NAME,
        "publicKey": PBK,
        "shortId": SHORT_ID,
        "spiderX": "/",
    });
    if fingerprint {
        reality["fingerprint"] = serde_json::json!("chrome");
    }
    serde_json::json!({
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "1.2.3.4",
                "port": 443,
                "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": reality,
            }
        }]
    })
    .to_string()
}

/// The options a fresh install runs with: nothing configured yet.
fn default_options() -> EngineOptions {
    EngineOptions::default()
}

fn prepared(input: &str) -> serde_json::Value {
    let json = prepare_runnable_config_with(input, &default_options())
        .unwrap_or_else(|error| panic!("did not prepare: {error}"));
    serde_json::from_str(&json).expect("the prepared config is JSON")
}

/// The vless outbound of a prepared config, whatever order the builder wrote
/// the outbound table in.
///
/// A share link stays in link form — `{"link": …}` with no `protocol`, which
/// the compiler refuses to see together — so the link itself identifies it.
fn proxy(config: &serde_json::Value) -> &serde_json::Value {
    config["outbounds"]
        .as_array()
        .expect("outbounds is an array")
        .iter()
        .find(|outbound| {
            outbound["protocol"] == "vless"
                || outbound["link"]
                    .as_str()
                    .is_some_and(|link| link.starts_with("vless://"))
        })
        .expect("a vless outbound")
}

fn link_field(link: &str, key: &str) -> Option<String> {
    let (_, rest) = link.split_once('?')?;
    let query = rest.split('#').next().unwrap_or(rest);
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value.to_string())
}

/// A share-link profile keeps its link for the parser to expand, so the
/// REALITY parameters have to still be *in the link*. Losing any of them
/// means the engine builds a tunnel that cannot authenticate.
fn assert_link_reality(config: &serde_json::Value) {
    let link = proxy(config)["link"].as_str().expect("a link outbound");
    assert_eq!(link_field(link, "security").as_deref(), Some("reality"));
    assert_eq!(link_field(link, "sni").as_deref(), Some(SERVER_NAME));
    assert_eq!(link_field(link, "pbk").as_deref(), Some(PBK));
    assert_eq!(link_field(link, "sid").as_deref(), Some(SHORT_ID));
    assert_eq!(
        link_field(link, "fp").as_deref(),
        Some("chrome"),
        "a REALITY link must carry a ClientHello shape, or its auth tag cannot be sent: {link}"
    );
}

/// Everything the tunnel cannot be built without, on a stored JSON profile.
fn assert_json_reality(config: &serde_json::Value) {
    let stream = &proxy(config)["streamSettings"];
    assert_eq!(
        stream["security"], "reality",
        "the profile stopped being REALITY: {stream}"
    );
    let reality = &stream["realitySettings"];
    assert_eq!(reality["serverName"], SERVER_NAME, "serverName lost");
    assert_eq!(reality["publicKey"], PBK, "publicKey lost");
    assert_eq!(reality["shortId"], SHORT_ID, "shortId lost");
    assert!(
        reality["fingerprint"]
            .as_str()
            .is_some_and(|f| !f.is_empty()),
        "REALITY without a fingerprint cannot carry its auth tag: {reality}"
    );
}

#[test]
fn a_full_reality_link_stays_reality() {
    let link = full_link();
    assert_link_reality(&prepared(&link));
    assert_eq!(validate_profile(&link, &default_options()), Ok(()));
}

#[test]
fn a_bare_reality_link_gains_a_client_hello_shape() {
    let link = bare_link();
    assert_link_reality(&prepared(&link));
    assert_eq!(validate_profile(&link, &default_options()), Ok(()));
}

#[test]
fn a_raw_json_reality_profile_stays_reality() {
    let json = raw_json(true);
    assert_json_reality(&prepared(&json));
    assert_eq!(validate_profile(&json, &default_options()), Ok(()));
}

#[test]
fn a_raw_json_reality_profile_without_a_fingerprint_gains_one() {
    let json = raw_json(false);
    assert_json_reality(&prepared(&json));
    assert_eq!(validate_profile(&json, &default_options()), Ok(()));
}

#[test]
fn a_plain_tls_link_is_not_given_a_shape_it_did_not_ask_for() {
    // TLS does not need a ClientHello shape to work, so an untouched setting
    // must not rewrite the link.
    let link = format!("vless://{UUID}@1.2.3.4:443?security=tls&sni={SERVER_NAME}&type=tcp#TLS");
    let config = prepared(&link);
    assert_eq!(
        proxy(&config)["link"].as_str(),
        Some(link.as_str()),
        "a TLS link was rewritten with a fingerprint nobody configured"
    );
    assert_eq!(validate_profile(&link, &default_options()), Ok(()));
}

#[test]
fn an_explicit_reality_shape_the_user_chose_is_kept() {
    // A REALITY-usable fingerprint the profile already carries must survive
    // preparation: defaulting it to chrome would override a deliberate choice.
    let link = format!(
        "vless://{UUID}@1.2.3.4:443?security=reality&sni={SERVER_NAME}&fp=firefox&pbk={PBK}&sid={SHORT_ID}&type=tcp#FF"
    );
    let config = prepared(&link);
    let prepared_link = proxy(&config)["link"].as_str().expect("a link outbound");
    assert_eq!(
        link_field(prepared_link, "fp").as_deref(),
        Some("firefox"),
        "an explicit firefox REALITY shape was overwritten: {prepared_link}"
    );
    assert_eq!(validate_profile(&link, &default_options()), Ok(()));

    // Same for raw JSON: firefox in realitySettings stays firefox.
    let mut json: serde_json::Value =
        serde_json::from_str(&raw_json(true)).expect("raw json parses");
    json["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] =
        serde_json::json!("firefox");
    let json = json.to_string();
    let config = prepared(&json);
    let stream = &proxy(&config)["streamSettings"];
    assert_eq!(
        stream["realitySettings"]["fingerprint"], "firefox",
        "an explicit firefox REALITY shape in JSON was overwritten: {stream}"
    );
    assert_eq!(validate_profile(&json, &default_options()), Ok(()));
}
