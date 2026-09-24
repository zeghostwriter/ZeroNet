//! Live clipboard check. `#[ignore]`d: it writes to the real clipboard.
#[test]
#[ignore = "writes to the real system clipboard"]
fn copy_reaches_the_system_clipboard() {
    use zeronet_tui::clipboard::Clipboard;
    let mut cb = Clipboard::new();
    println!("system clipboard available: {}", cb.has_system_clipboard());

    let marker = format!("zeronet-clip-test-{}", std::process::id());
    match cb.copy(&marker) {
        Ok(route) => println!("copied via {route:?}"),
        Err(e) => panic!("copy failed: {e}"),
    }

    // Read it back through the app's own path...
    assert_eq!(cb.paste().unwrap(), marker, "in-app paste mismatch");

    // ...and through an external tool, which is what proves it left the app.
    let external = std::process::Command::new("wl-paste").arg("-n").output();
    match external {
        Ok(out) => {
            let got = String::from_utf8_lossy(&out.stdout);
            println!("wl-paste returned: {:?}", got.trim());
            assert_eq!(got.trim(), marker, "the system clipboard was not updated");
        }
        Err(e) => println!("wl-paste unavailable ({e}); in-app path verified only"),
    }
}
