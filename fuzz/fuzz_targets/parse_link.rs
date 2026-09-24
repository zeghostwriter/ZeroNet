#![no_main]
//! Fuzz the single share-link parser (`vless://`, `vmess://`, `ss://`, ...).
//!
//! Share links are pasted from untrusted sources, so a malformed link must
//! come back as `Err`, never a panic. The link is percent-, base64- and
//! query-decoded along several branches; this drives arbitrary text through
//! all of them.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = zero_config::parse_link(text);
});
