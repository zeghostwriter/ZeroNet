//! Compresses the embedded Iranian-ISP range table at build time.
//!
//! `data/ir_isps.tsv` is a ~600 KB plain-text table of IPv4 ranges and their
//! ISP names. Embedding it verbatim with `include_str!` put every one of those
//! bytes in the shipped binary's read-only data, where it is the single largest
//! `.rodata` item on both the desktop builds and the Android library — and
//! download size is what hurts most on an Iranian mobile link.
//!
//! Here it is zstd-compressed (about an eighth of the original) into the
//! crate's `OUT_DIR`; `meta::isp` embeds that blob instead and inflates it once
//! on first lookup. The zstd decoder is already linked by `zero-security`, so
//! the shipped code grows by nothing while the data shrinks by roughly half a
//! megabyte.
//!
//! The round-trip is checked here so a corrupt or mis-encoded blob fails the
//! build rather than the scanner at run time.

use std::io::Read;
use std::path::PathBuf;
use std::{env, fs};

// Best ratio; build-time cost is irrelevant and only paid when the table changes.
const ZSTD_LEVEL: i32 = 19;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("data/ir_isps.tsv");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed=build.rs");

    let raw = fs::read(&source).unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
    let compressed = zstd::encode_all(raw.as_slice(), ZSTD_LEVEL).expect("zstd compress ir_isps");

    // Fail the build, not the scanner, if the blob does not round-trip.
    let mut back = Vec::with_capacity(raw.len());
    zstd::Decoder::new(compressed.as_slice())
        .expect("zstd decoder")
        .read_to_end(&mut back)
        .expect("zstd decompress ir_isps");
    assert_eq!(
        back, raw,
        "ir_isps.tsv does not survive the zstd round-trip"
    );

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("ir_isps.tsv.zst");
    fs::write(&out, &compressed).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
}
