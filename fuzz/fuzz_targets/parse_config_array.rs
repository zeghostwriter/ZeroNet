#![no_main]
//! Fuzz the JSON config parser and the graph compiler.
//!
//! The parser is the widest attack surface: it takes attacker-influenced
//! subscription bodies. It must reject anything malformed with an `Err`, never
//! panic, never loop forever, and never build an invalid runtime graph. This
//! target feeds arbitrary bytes through the whole `text -> config -> compiled
//! generation` path and asserts only that it returns rather than crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(configs) = zero_config::parse_config_array(text) {
        // Every parsed config must also survive compilation into a runtime
        // generation without panicking.
        for (_, config, _) in configs {
            let _ = zero_config::RuntimeGeneration::compile(config, zero_core::GenerationId(1));
        }
    }
});
