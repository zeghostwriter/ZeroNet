//! ClientHello shape parity against the pinned oracle (PLAN-01 phase 7).
//!
//! Every other test in this repository asks whether a connection *works*. This
//! one asks what it looks like, which for a censorship-resistant proxy is the
//! question that decides whether it keeps working. A stock Rust TLS hello is
//! itself a fingerprint (PLAN-02 §2); shaping it like Chrome is the point of
//! carrying a 4,500-line uTLS profile corpus at all. If the shaping drifts —
//! because rustls reordered an extension, because a dependency bump changed a
//! default, because a profile was edited — nothing fails. Traffic still flows.
//! It just becomes identifiable, and the user finds out when their server is
//! blocked.
//!
//! So the comparison is against Xray's own uTLS output for the same profile
//! name, captured from the pinned binary. Fields that are *supposed* to differ
//! per connection — randoms, session id, key-share material, GREASE draws —
//! are normalised away; everything that constitutes the shape is compared
//! exactly.
//!
//! ## The one divergence, stated plainly
//!
//! The cipher-suite list is *not* identical, and cannot be made so on this
//! path. uTLS emits a browser's full list including the TLS 1.2 ECDHE and
//! RSA/CBC suites that a TLS 1.3 connection never uses; the pinned
//! `shaped-rustls` revision refuses to advertise a suite the configured
//! provider could not negotiate, so those suites are dropped and Zray's list
//! is about half the length. That is visible to a classifier.
//!
//! Rather than skip the field — which would let the divergence grow unnoticed
//! — these tests assert the exact relationship that does hold: Zray's list is
//! uTLS's list, in uTLS's order, filtered to the suites rustls implements. A
//! reordering, an addition, or a drop of a suite rustls *does* implement all
//! fail here. If the fork later gains shape-only advertisement, the assertion
//! tightens to equality by deleting the filter.
//!
//! The REALITY path does not have this problem: it is built on the TLS 1.3
//! stack this project owns and emits the legacy tail verbatim, which is the
//! whole argument of PLAN-01 Decision 2.
//!
//! ```bash
//! cargo test -p zero-runtime --test fingerprint_oracle -- --ignored --test-threads=1
//! ```

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SERVER_NAME: &str = "example.com";

fn oracle_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_XRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        return Err(format!(
            "ZRAY_XRAY_BINARY points at {path}, which does not exist"
        ));
    }
    match Command::new("xray").arg("version").output() {
        Ok(output) if output.status.success() => Ok("xray".into()),
        _ => Err("no `xray` on PATH and ZRAY_XRAY_BINARY is unset".into()),
    }
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Oracle {
    child: Child,
    _directory: std::path::PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_oracle(binary: &str, config: Value) -> Oracle {
    let directory = std::env::temp_dir().join(format!(
        "zray-fingerprint-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.json");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
        .unwrap();
    file.sync_all().unwrap();
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start the oracle: {error}"));
    Oracle {
        child,
        _directory: directory,
    }
}

// ------------------------------------------------------------------- capture

/// Accept one connection and return the first TLS record it carries.
///
/// The peer is left hanging deliberately: the hello is the whole subject, and
/// answering it would only invite a handshake that cannot complete.
async fn capture_first_record(listener: TcpListener) -> Result<Vec<u8>, String> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .map_err(|_| "nothing connected to the capture listener".to_string())?
        .map_err(|error| format!("accept: {error}"))?;

    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .map_err(|_| "no TLS record header arrived".to_string())?
        .map_err(|error| format!("record header: {error}"))?;
    if header[0] != 22 {
        return Err(format!("first record is type {}, not handshake", header[0]));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; length];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| "the record body did not arrive".to_string())?
        .map_err(|error| format!("record body: {error}"))?;

    let mut record = header.to_vec();
    record.extend_from_slice(&body);
    Ok(record)
}

/// Drive the oracle into dialling the capture listener, and return its hello.
async fn oracle_client_hello(binary: &str, fingerprint: &str, alpn: &[&str]) -> Vec<u8> {
    let capture = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let capture_port = capture.local_addr().unwrap().port();
    let socks_port = free_port();

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": false},
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": capture_port,
                    "users": [{"id": UUID, "encryption": "none"}],
                }]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": SERVER_NAME,
                        "fingerprint": fingerprint,
                        "alpn": alpn,
                    },
                },
            }],
        }),
    );

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    let collector = tokio::spawn(capture_first_record(capture));

    // Nudge the oracle into opening the outbound. The SOCKS request never
    // completes, which is fine — the dial is all this needs.
    let prod = tokio::spawn(async move {
        for _ in 0..100 {
            if let Ok(mut stream) = TcpStream::connect(socks).await {
                let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_ok() {
                    let request = [
                        0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                        b'c', b'o', b'm', 0x01, 0xbb,
                    ];
                    let _ = stream.write_all(&request).await;
                    // Hold the connection while the outbound dials.
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let hello = collector.await.unwrap().unwrap_or_else(|reason| {
        panic!("could not capture the oracle's hello for {fingerprint}: {reason}")
    });
    prod.abort();
    hello
}

/// Zray's hello for the same profile, straight from the TLS backend.
fn zray_client_hello(fingerprint: &str, alpn: &[&str]) -> Vec<u8> {
    let params = zero_security::TlsParams::new(SERVER_NAME)
        .with_fingerprint_name(fingerprint)
        .with_alpn(alpn);
    let config = zero_security::client_config(&params);
    let name = rustls::pki_types::ServerName::try_from(SERVER_NAME.to_owned()).unwrap();
    let mut connection = rustls::ClientConnection::new(config, name)
        .unwrap_or_else(|error| panic!("{fingerprint}: {error}"));
    let mut flight = Vec::new();
    connection.write_tls(&mut flight).unwrap();
    flight
}

// ----------------------------------------------------------------- normalise

/// GREASE values are `0x?a?a` with both bytes equal (RFC 8701). They are drawn
/// per connection, so their *positions* are the shape and their values are not.
const GREASE: u16 = 0xdada;

fn normalise_grease(value: u16) -> u16 {
    let [high, low] = value.to_be_bytes();
    if high == low && (high & 0x0f) == 0x0a {
        GREASE
    } else {
        value
    }
}

/// The parts of a ClientHello that constitute its shape.
#[derive(Debug, PartialEq, Eq)]
struct HelloShape {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    compression: Vec<u8>,
    /// Extension types, in order. Order is load-bearing: it is one of the
    /// strongest signals a classifier has.
    extension_types: Vec<u16>,
    /// Extension bodies whose content is fixed for a profile, keyed by type.
    fixed_bodies: Vec<(u16, Vec<u8>)>,
    /// `key_share` groups with their key lengths, but not the key material.
    key_share_groups: Vec<(u16, usize)>,
}

/// Extensions whose body is a property of the profile rather than of the
/// connection, so it can be compared byte for byte.
const FIXED_BODY_EXTENSIONS: &[u16] = &[
    10,    // supported_groups
    11,    // ec_point_formats
    13,    // signature_algorithms
    16,    // application_layer_protocol_negotiation
    23,    // extended_master_secret
    28,    // record_size_limit
    27,    // compress_certificate
    43,    // supported_versions
    45,    // psk_key_exchange_modes
    5,     // status_request
    18,    // signed_certificate_timestamp
    17513, // application_settings
    65281, // renegotiation_info
];

fn parse_shape(record: &[u8]) -> Result<HelloShape, String> {
    if record.len() < 5 || record[0] != 22 {
        return Err("not a handshake record".into());
    }
    let body = &record[5..];
    if body.first() != Some(&1) {
        return Err("not a ClientHello".into());
    }
    let mut at = 4; // handshake type + 3-byte length
    let legacy_version = read_u16(body, &mut at)?;
    at += 32; // random
    let session_id_len = *body.get(at).ok_or("truncated session id")? as usize;
    at += 1 + session_id_len;

    let suites_len = read_u16(body, &mut at)? as usize;
    let mut cipher_suites = Vec::new();
    let suites_end = at + suites_len;
    while at < suites_end {
        cipher_suites.push(normalise_grease(read_u16(body, &mut at)?));
    }

    let compression_len = *body.get(at).ok_or("truncated compression")? as usize;
    at += 1;
    let compression = body
        .get(at..at + compression_len)
        .ok_or("truncated compression methods")?
        .to_vec();
    at += compression_len;

    let extensions_len = read_u16(body, &mut at)? as usize;
    let extensions_end = at + extensions_len;
    let mut extension_types = Vec::new();
    let mut fixed_bodies = Vec::new();
    let mut key_share_groups = Vec::new();

    while at + 4 <= extensions_end {
        let raw_type = read_u16(body, &mut at)?;
        let length = read_u16(body, &mut at)? as usize;
        let extension = body
            .get(at..at + length)
            .ok_or("truncated extension body")?
            .to_vec();
        at += length;
        let kind = normalise_grease(raw_type);
        extension_types.push(kind);

        if kind == 51 {
            // key_share: compare which groups are offered and how long each
            // key is, never the key itself.
            let mut inner = 2usize;
            while inner + 4 <= extension.len() {
                let group =
                    normalise_grease(u16::from_be_bytes([extension[inner], extension[inner + 1]]));
                let key_len =
                    u16::from_be_bytes([extension[inner + 2], extension[inner + 3]]) as usize;
                key_share_groups.push((group, key_len));
                inner += 4 + key_len;
            }
        } else if FIXED_BODY_EXTENSIONS.contains(&kind) {
            fixed_bodies.push((kind, normalise_body(kind, extension)));
        }
    }

    Ok(HelloShape {
        legacy_version,
        cipher_suites,
        compression,
        extension_types,
        fixed_bodies,
        key_share_groups,
    })
}

/// Normalise GREASE inside an extension body.
///
/// `supported_groups` and `supported_versions` carry a GREASE entry of their
/// own, drawn per connection exactly like the ones in the cipher-suite list.
/// Comparing those raw would make every run disagree for the one reason that
/// is not a difference.
fn normalise_body(kind: u16, mut body: Vec<u8>) -> Vec<u8> {
    // Both are a length prefix followed by a list of u16s; the prefix is two
    // bytes for supported_groups and one for supported_versions.
    let start = match kind {
        10 => 2,
        43 => 1,
        _ => return body,
    };
    let mut at = start;
    while at + 2 <= body.len() {
        let value = normalise_grease(u16::from_be_bytes([body[at], body[at + 1]]));
        body[at..at + 2].copy_from_slice(&value.to_be_bytes());
        at += 2;
    }
    body
}

fn read_u16(body: &[u8], at: &mut usize) -> Result<u16, String> {
    let value = body
        .get(*at..*at + 2)
        .ok_or("truncated while reading a u16")?;
    *at += 2;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

/// Suites the rustls build actually implements, so the oracle's list can be
/// reduced to what Zray is able to advertise.
///
/// Listed explicitly rather than read back from Zray's own output: deriving
/// the expectation from the thing under test would make the comparison pass by
/// construction.
const RUSTLS_IMPLEMENTED_SUITES: &[u16] = &[
    0x1301, // TLS13_AES_128_GCM_SHA256
    0x1302, // TLS13_AES_256_GCM_SHA384
    0x1303, // TLS13_CHACHA20_POLY1305_SHA256
    0xc02b, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02c, // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc02f, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca8, // ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xcca9, // ECDHE_ECDSA_WITH_CHACHA20_POLY1305
];

/// Report the first difference in terms a reader can act on.
fn compare(name: &str, oracle: &HelloShape, zray: &HelloShape, shuffles: bool) {
    if shuffles {
        // Chrome has permuted its extensions per connection since 110, and
        // uTLS reproduces that. Comparing the order would fail at random; not
        // comparing the *set* would miss a missing or extra extension. The
        // anchors are not shuffled either, so they are still compared in place.
        let mut oracle_set = oracle.extension_types.clone();
        let mut zray_set = zray.extension_types.clone();
        oracle_set.sort_unstable();
        zray_set.sort_unstable();
        assert_eq!(
            oracle_set, zray_set,
            "{name}: extension *set* differs (order is shuffled, membership is not).\n  \
             uTLS: {:?}\n  Zray: {:?}",
            oracle.extension_types, zray.extension_types
        );
        assert_eq!(
            oracle.extension_types.first(),
            zray.extension_types.first(),
            "{name}: the shuffle leaves the leading extension fixed, and these differ"
        );
        assert_eq!(
            oracle.extension_types.last(),
            zray.extension_types.last(),
            "{name}: the shuffle leaves the trailing extension fixed, and these differ"
        );
    } else {
        assert_eq!(
            oracle.extension_types, zray.extension_types,
            "{name}: extension order differs.\n  uTLS: {:?}\n  Zray: {:?}",
            oracle.extension_types, zray.extension_types
        );
    }

    // See the module documentation: equality is unreachable here, so assert
    // the exact relationship that is.
    let expected: Vec<u16> = oracle
        .cipher_suites
        .iter()
        .copied()
        .filter(|suite| *suite == GREASE || RUSTLS_IMPLEMENTED_SUITES.contains(suite))
        .collect();
    assert_eq!(
        expected, zray.cipher_suites,
        "{name}: cipher suites diverge beyond the known rustls filter.\n  \
         uTLS:     {:?}\n  expected: {expected:?}\n  Zray:     {:?}",
        oracle.cipher_suites, zray.cipher_suites
    );
    assert!(
        zray.cipher_suites.len() < oracle.cipher_suites.len(),
        "{name}: Zray now advertises as many suites as uTLS. If the fork \
         gained shape-only advertisement, delete the filter above and assert \
         equality — this divergence should not be retired quietly"
    );
    assert_eq!(
        oracle.legacy_version, zray.legacy_version,
        "{name}: legacy_version differs"
    );
    assert_eq!(
        oracle.compression, zray.compression,
        "{name}: compression methods differ"
    );
    assert_eq!(
        oracle.key_share_groups, zray.key_share_groups,
        "{name}: key_share groups or key lengths differ"
    );
    for (kind, expected) in &oracle.fixed_bodies {
        let actual = zray
            .fixed_bodies
            .iter()
            .find(|(candidate, _)| candidate == kind)
            .map(|(_, body)| body);
        assert_eq!(
            Some(expected),
            actual,
            "{name}: extension {kind} body differs"
        );
    }
}

async fn assert_profile_matches(binary: &str, fingerprint: &str) {
    let alpn = ["h2", "http/1.1"];

    // Two hellos from each side, because whether a profile shuffles its
    // extensions is itself part of its shape. A client that sends a fixed
    // order where the browser it claims to be sends a random one is as
    // identifiable as one that gets the order wrong.
    let oracle_first = parse_shape(&oracle_client_hello(binary, fingerprint, &alpn).await)
        .unwrap_or_else(|reason| panic!("{fingerprint}: oracle hello unparseable: {reason}"));
    let oracle_second = parse_shape(&oracle_client_hello(binary, fingerprint, &alpn).await)
        .unwrap_or_else(|reason| panic!("{fingerprint}: oracle hello unparseable: {reason}"));
    let zray_first = parse_shape(&zray_client_hello(fingerprint, &alpn))
        .unwrap_or_else(|reason| panic!("{fingerprint}: Zray hello unparseable: {reason}"));
    let zray_second = parse_shape(&zray_client_hello(fingerprint, &alpn))
        .unwrap_or_else(|reason| panic!("{fingerprint}: Zray hello unparseable: {reason}"));

    let oracle_shuffles = oracle_first.extension_types != oracle_second.extension_types;
    let zray_shuffles = zray_first.extension_types != zray_second.extension_types;
    assert_eq!(
        oracle_shuffles,
        zray_shuffles,
        "{fingerprint}: uTLS {} its extensions between connections and Zray {}. \
         Whether the order varies is a fingerprint in its own right.",
        if oracle_shuffles { "permutes" } else { "fixes" },
        if zray_shuffles { "permutes" } else { "fixes" },
    );

    compare(fingerprint, &oracle_first, &zray_first, oracle_shuffles);
    compare(fingerprint, &oracle_second, &zray_second, oracle_shuffles);
}

macro_rules! fingerprint {
    ($name:ident, $profile:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "needs an Xray binary; see the module documentation"]
        async fn $name() {
            let binary = oracle_binary().unwrap_or_else(|reason| {
                panic!("the fingerprint comparison cannot run: {reason}");
            });
            assert_profile_matches(&binary, $profile).await;
        }
    };
}

fingerprint!(chrome_hello_matches_utls, "chrome");
fingerprint!(firefox_hello_matches_utls, "firefox");
fingerprint!(safari_hello_matches_utls, "safari");
fingerprint!(edge_hello_matches_utls, "edge");
fingerprint!(ios_hello_matches_utls, "ios");

/// The comparison has to be able to fail, or a pass means nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn two_different_profiles_do_not_compare_equal() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the fingerprint comparison cannot run: {reason}");
    });
    let alpn = ["h2", "http/1.1"];
    let chrome = parse_shape(&oracle_client_hello(&binary, "chrome", &alpn).await).unwrap();
    let firefox = parse_shape(&oracle_client_hello(&binary, "firefox", &alpn).await).unwrap();
    assert_ne!(
        chrome, firefox,
        "Chrome and Firefox produced identical shapes, so this comparison \
         cannot distinguish anything and every other case here is vacuous"
    );
}
