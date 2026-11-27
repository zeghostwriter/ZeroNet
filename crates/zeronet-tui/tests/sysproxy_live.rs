//! Live system-proxy test.
//!
//! `#[ignore]`d because it changes real desktop settings. Run explicitly:
//!
//! ```text
//! cargo test -p zeronet-tui --test sysproxy_live -- --ignored --nocapture
//! ```
//!
//! Every key it touches is read first and written back at the end, so a
//! machine that already had a proxy configured is left exactly as it was.

use zeronet_tui::sysproxy::{self, Backend, ProxyEndpoints, SystemProxyMode};

/// Ports well away from anything real, so a half-applied state cannot send
/// the machine's traffic somewhere unexpected.
fn endpoints() -> ProxyEndpoints {
    ProxyEndpoints {
        http_port: 19809,
        socks_port: 19808,
        pac_port: 19080,
    }
}

const KDE_KEYS: [&str; 6] = [
    "ProxyType",
    "httpProxy",
    "httpsProxy",
    "socksProxy",
    "NoProxyFor",
    "Proxy Config Script",
];

fn kde_binary(write: bool) -> &'static str {
    let candidates: [&str; 2] = if write {
        ["kwriteconfig6", "kwriteconfig5"]
    } else {
        ["kreadconfig6", "kreadconfig5"]
    };
    for candidate in candidates {
        if std::process::Command::new(candidate)
            .arg("--help")
            .output()
            .is_ok()
        {
            return candidate;
        }
    }
    candidates[0]
}

fn kde_read(key: &str) -> String {
    let out = std::process::Command::new(kde_binary(false))
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
        ])
        .output()
        .expect("kreadconfig runs");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[allow(clippy::needless_return)]
fn kde_write(key: &str, value: &str) {
    let mut cmd = std::process::Command::new(kde_binary(true));
    cmd.args([
        "--file",
        "kioslaverc",
        "--group",
        "Proxy Settings",
        "--key",
        key,
    ]);
    if value.is_empty() {
        // An empty value means the key was absent; delete rather than write
        // a blank, which KDE treats differently.
        cmd.arg("--delete");
    } else {
        cmd.arg(value);
    }
    let _ = cmd.output();
}

fn gnome_read(key: &str) -> String {
    let out = std::process::Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", key])
        .output()
        .expect("gsettings runs");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
#[ignore = "changes real desktop proxy settings"]
fn applying_and_clearing_round_trips_the_desktop_settings() {
    let backend = sysproxy::detect_backend();
    println!("detected backend: {backend}");

    match backend {
        Backend::Kde => {
            // Snapshot everything first, so whatever happens the machine can
            // be put back.
            let original: Vec<(String, String)> = KDE_KEYS
                .iter()
                .map(|k| (k.to_string(), kde_read(k)))
                .collect();
            println!("original settings: {original:?}");

            let restore = || {
                for (key, value) in &original {
                    kde_write(key, value);
                }
            };

            // ---- manual mode
            let applied = sysproxy::apply(SystemProxyMode::Manual, endpoints());
            if let Err(e) = &applied {
                restore();
                panic!("manual mode failed: {e}");
            }
            assert_eq!(kde_read("ProxyType"), "1", "ProxyType should be manual");
            assert!(
                kde_read("httpProxy").contains("19809"),
                "httpProxy = {:?}",
                kde_read("httpProxy")
            );
            assert!(
                kde_read("socksProxy").contains("19808"),
                "socksProxy = {:?}",
                kde_read("socksProxy")
            );
            println!("manual mode applied correctly");

            // ---- PAC mode
            let applied = sysproxy::apply(SystemProxyMode::Pac, endpoints());
            if let Err(e) = &applied {
                restore();
                panic!("PAC mode failed: {e}");
            }
            assert_eq!(kde_read("ProxyType"), "2", "ProxyType should be PAC");
            let script = kde_read("Proxy Config Script");
            assert!(
                script.contains("19080") && script.contains("proxy.pac"),
                "Proxy Config Script = {script:?}"
            );
            println!("PAC mode applied correctly: {script}");

            // ---- clear mode
            let cleared = sysproxy::apply(SystemProxyMode::Clear, endpoints());
            if let Err(e) = &cleared {
                restore();
                panic!("clear mode failed: {e}");
            }
            assert_eq!(kde_read("ProxyType"), "0", "clear should leave ProxyType 0");
            println!("clear mode applied correctly");

            // ---- do not change
            //
            // The whole point of the mode: applying it writes nothing at all.
            // Put a recognisable value in place first and prove it survives.
            kde_write("httpProxy", "http://127.0.0.1 45678");
            let before = kde_read("httpProxy");
            let unchanged = sysproxy::apply(SystemProxyMode::Unmanaged, endpoints());
            if let Err(e) = &unchanged {
                restore();
                panic!("unmanaged mode failed: {e}");
            }
            assert_eq!(
                kde_read("httpProxy"),
                before,
                "'do not change' modified the settings"
            );
            println!("'do not change' left the settings alone");

            // ---- snapshot / restore
            //
            // This is what makes reverting non-destructive: a machine whose
            // proxy belongs to another tool must get its own values back, not
            // "no proxy".
            kde_write("ProxyType", "1");
            kde_write("httpProxy", "http://127.0.0.1 45678");
            let snap = sysproxy::snapshot();
            assert_eq!(
                sysproxy::restore_strategy(&snap),
                sysproxy::RestoreStrategy::Replay
            );

            if let Err(e) = sysproxy::apply(SystemProxyMode::Manual, endpoints()) {
                restore();
                panic!("manual mode failed: {e}");
            }
            assert!(kde_read("httpProxy").contains("19809"));

            if let Err(e) = sysproxy::restore(&snap) {
                restore();
                panic!("restore failed: {e}");
            }
            assert_eq!(
                kde_read("httpProxy"),
                "http://127.0.0.1 45678",
                "restore did not put the original value back"
            );
            assert_eq!(kde_read("ProxyType"), "1");
            println!("snapshot/restore round-tripped a third-party configuration");

            restore();
            for (key, value) in &original {
                assert_eq!(&kde_read(key), value, "{key} was not restored");
            }
            println!("original settings restored");
        }

        Backend::Gnome => {
            let original_mode = gnome_read("mode");
            let original_url = gnome_read("autoconfig-url");
            println!("original: mode={original_mode} url={original_url}");

            let restore = || {
                let _ = std::process::Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy", "mode", &original_mode])
                    .output();
                let _ = std::process::Command::new("gsettings")
                    .args([
                        "set",
                        "org.gnome.system.proxy",
                        "autoconfig-url",
                        &original_url,
                    ])
                    .output();
            };

            if let Err(e) = sysproxy::apply(SystemProxyMode::Manual, endpoints()) {
                restore();
                panic!("manual mode failed: {e}");
            }
            assert!(gnome_read("mode").contains("manual"));

            if let Err(e) = sysproxy::apply(SystemProxyMode::Pac, endpoints()) {
                restore();
                panic!("PAC mode failed: {e}");
            }
            assert!(gnome_read("mode").contains("auto"));
            assert!(gnome_read("autoconfig-url").contains("19080"));

            if let Err(e) = sysproxy::clear() {
                restore();
                panic!("clear failed: {e}");
            }
            assert!(gnome_read("mode").contains("none"));

            restore();
            assert_eq!(gnome_read("mode"), original_mode);
        }

        other => {
            println!("no live check for {other}; the unit tests cover the rest");
        }
    }
}

#[tokio::test]
#[ignore = "binds a local port"]
async fn the_pac_server_answers_a_real_http_request() {
    let endpoints = endpoints();
    let server = sysproxy::PacServer::start(endpoints.pac_port, sysproxy::pac_script(endpoints))
        .await
        .expect("PAC server starts");

    // Fetch it the way a browser would.
    let body = zeronet_tui::subscription::fetch_feed(&server.url()).await;
    // A PAC script is not a subscription, so parsing yields nothing — but the
    // fetch itself must succeed, which is what proves the server is serving.
    match body {
        Ok(feed) => {
            assert!(feed.profiles.is_empty(), "a PAC file is not a node list");
            println!("PAC served and fetched successfully");
        }
        Err(e) => panic!("could not fetch the PAC file: {e}"),
    }
}
