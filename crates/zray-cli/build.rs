//! Lets the release workflow stamp the version it is building (`v0.2.1`) into
//! `zray version`; a local build reports the crate version.

fn main() {
    println!("cargo:rerun-if-env-changed=ZERONET_VERSION");
    if let Ok(version) = std::env::var("ZERONET_VERSION") {
        let version = version.trim().trim_start_matches(['v', 'V']);
        if !version.is_empty() {
            println!("cargo:rustc-env=ZRAY_APP_VERSION={version}");
        }
    }
}
