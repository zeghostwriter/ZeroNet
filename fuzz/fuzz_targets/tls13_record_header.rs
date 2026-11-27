#![no_main]
//! The peer supplies the 16-bit length that says how much ciphertext the
//! reader will take, so it must never come back above the TLS bound.

use libfuzzer_sys::fuzz_target;
use zero_security::tls13::record::parse_header;
use zero_security::tls13::MAX_CIPHERTEXT;

fuzz_target!(|data: &[u8]| {
    // A header that is not exactly five bytes is rejected, so `Ok` is rare; what
    // matters is that the length it does return has already been bounded.
    if let Ok((_, body_len)) = parse_header(data) {
        assert!(
            body_len <= MAX_CIPHERTEXT,
            "record length past the TLS bound"
        );
    }
});
