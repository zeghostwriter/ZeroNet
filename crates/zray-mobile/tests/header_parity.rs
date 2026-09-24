//! The C header and the Rust entry points must not drift.
//!
//! `include/zray.h` is written by hand. That is a deliberate choice — a
//! generated header would be one more build-time tool in a crate whose whole
//! job is to be simple to link against — but it means nothing stops the two
//! from disagreeing, and the failure mode is nasty: a host compiled against a
//! stale header links successfully and then calls a function with the wrong
//! signature, or tests a status code that no longer means what it did.
//!
//! So the header is treated as an interface definition and checked against the
//! implementation. Adding an entry point without declaring it, or changing a
//! status value on one side, fails here.

use std::collections::BTreeMap;

const HEADER: &str = include_str!("../include/zray.h");
const SOURCE: &str = include_str!("../src/lib.rs");

/// `#define ZRAY_X 3` → `("ZRAY_X", 3)`.
fn header_constants() -> BTreeMap<String, i64> {
    HEADER
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("#define ")?;
            let (name, value) = rest.split_once(char::is_whitespace)?;
            if !name.starts_with("ZRAY_") {
                return None;
            }
            Some((name.to_owned(), value.trim().parse().ok()?))
        })
        .collect()
}

/// `pub const ZRAY_X: c_int = 3;` → `("ZRAY_X", 3)`.
fn rust_constants() -> BTreeMap<String, i64> {
    SOURCE
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub const ZRAY_")?;
            let (name, rest) = rest.split_once(':')?;
            let value = rest.split('=').nth(1)?.trim().trim_end_matches(';');
            Some((format!("ZRAY_{name}"), value.parse().ok()?))
        })
        .collect()
}

/// Every `#[no_mangle] extern "C"` function name in the implementation.
fn rust_exports() -> Vec<String> {
    let mut exports = Vec::new();
    let mut lines = SOURCE.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() != "#[no_mangle]" {
            continue;
        }
        let Some(signature) = lines.peek() else {
            continue;
        };
        let Some(rest) = signature.split("fn ").nth(1) else {
            continue;
        };
        if let Some(name) = rest.split('(').next() {
            exports.push(name.trim().to_owned());
        }
    }
    exports
}

#[test]
fn every_status_code_means_the_same_thing_on_both_sides() {
    let header = header_constants();
    let rust = rust_constants();
    assert!(
        !rust.is_empty(),
        "no status constants were found in the implementation; the parser \
         above has stopped matching the source"
    );
    assert_eq!(
        rust, header,
        "the header's status codes and the implementation's disagree.\n  \
         implementation: {rust:?}\n  header:         {header:?}"
    );
}

#[test]
fn every_exported_function_is_declared_in_the_header() {
    let exports = rust_exports();
    assert!(
        exports.len() >= 8,
        "only {} exported functions were found; the parser above has stopped \
         matching the source",
        exports.len()
    );
    for name in &exports {
        assert!(
            HEADER.contains(name.as_str()),
            "{name} is exported from the library but not declared in \
             include/zray.h, so a host cannot call it"
        );
    }
}

#[test]
fn the_header_declares_nothing_the_library_does_not_export() {
    // The dangerous direction: a host that compiles against a declaration
    // with no symbol behind it fails at link time if it is lucky, and at
    // `dlsym` time if it is not.
    let exports = rust_exports();
    for line in HEADER.lines() {
        let line = line.trim();
        // Declarations end in `);` and are not typedefs or comments.
        if !line.ends_with(");") || line.starts_with("typedef") || line.starts_with('*') {
            continue;
        }
        let Some(name) = line
            .split('(')
            .next()
            .and_then(|prefix| prefix.split_whitespace().last())
        else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if !name.starts_with("zray_") {
            continue;
        }
        assert!(
            exports.iter().any(|export| export == name),
            "the header declares {name}, but the library exports no such symbol"
        );
    }
}

#[test]
fn the_callback_signature_matches_the_platforms_convention() {
    // Android's `VpnService.protect` returns a boolean, so non-zero means
    // success here. Inverting it would silently disable protection on every
    // socket — and the failure would look like a routing problem, not a bug.
    assert!(
        HEADER.contains("typedef int32_t (*zray_protect_callback)(int32_t fd, void *context);"),
        "the callback typedef changed shape; the Rust side is \
         `extern \"C\" fn(fd: c_int, context: *mut c_void) -> c_int`"
    );
    assert!(
        SOURCE.contains(
            "pub type ProtectCallback = extern \"C\" fn(fd: c_int, context: *mut c_void) -> c_int;"
        ),
        "the Rust callback type changed shape; update include/zray.h to match"
    );
}
