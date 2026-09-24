#![no_main]
//! Fuzz the Shadowsocks 2022 key decoder.
//!
//! `decode_user_key` runs a hand-rolled base64 decoder over an untrusted PSK
//! string before checking the length. That decoder is the parsing surface a
//! bad config reaches first, so it must reject anything malformed with an
//! `Err` and never panic or index out of bounds. Both AEAD methods are
//! exercised because they differ only in the expected key length.

use libfuzzer_sys::fuzz_target;
use zero_protocol::shadowsocks2022::{decode_user_key, Method};

fuzz_target!(|data: &[u8]| {
    let Ok(password) = std::str::from_utf8(data) else {
        return;
    };
    let _ = decode_user_key(password, Method::Aes128Gcm);
    let _ = decode_user_key(password, Method::Aes256Gcm);
    let _ = Method::parse(password);
});
