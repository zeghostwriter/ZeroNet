#![no_main]
//! Fuzz the multi-line subscription parser.
//!
//! A subscription is a base64 blob of newline-separated share links from a
//! remote server. It returns a per-line result vector rather than a single
//! error, so a bad line must not abort the batch or panic; this drives
//! arbitrary bytes through the base64 decode and the per-line split.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = zero_config::parse_subscription(text);
});
