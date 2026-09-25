//! Embeds the ZeroNet icon and version information into the Windows
//! executable, so Explorer, the taskbar and the console window show the
//! logo instead of a blank program icon.

fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icons/zeronet.ico");
    // The release workflow names the version it is building (`v0.1.5`);
    // the app reports it without the `v` and compares it with the latest
    // release to offer updates. See `update::CURRENT_VERSION`.
    println!("cargo:rerun-if-env-changed=ZERONET_VERSION");
    if let Ok(version) = std::env::var("ZERONET_VERSION") {
        let version = version.trim().trim_start_matches(['v', 'V']);
        if !version.is_empty() {
            println!("cargo:rustc-env=ZERONET_APP_VERSION={version}");
        }
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon("../../packaging/icons/zeronet.ico")
        .set("ProductName", "ZeroNet")
        .set("FileDescription", "ZeroNet")
        .set("CompanyName", "ZeroNet");
    // A missing resource compiler costs the icon, not the build.
    if let Err(error) = resource.compile() {
        println!("cargo:warning=the Windows icon was not embedded: {error}");
    }
}
