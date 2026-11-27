//! Checking a downloaded server program before it is installed.
//!
//! The server program is downloaded by the *server*, because GitHub is often
//! unreachable from where the app runs. That makes the download untrusted
//! until proven otherwise, and the proof is a signature the app checks itself:
//!
//! 1. The server fetches the release's `SHA256SUMS.txt` and its detached
//!    signature and hands both to the app.
//! 2. The app verifies the signature with the public key compiled into it (the
//!    same key that vouches for its server lists) and reads the expected hash
//!    of the right file out of the list.
//! 3. The server downloads the program and compares its hash with that value
//!    before installing; a mismatch deletes it.
//!
//! So a GitHub account that is not ours, a CDN or a network in the middle could
//! serve any bytes they like and still get nothing installed.

/// The signed list's line for `asset`, as the hash it names.
pub fn expected_hash(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let (hash, name) = (parts.next()?, parts.next()?);
        // `sha256sum` marks binary files with a leading `*`.
        (name.trim_start_matches('*') == asset
            && hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hash.to_ascii_lowercase())
    })
}

/// Whether `signature` (an `ed25519:<hex>` line) vouches for `sums` under the
/// app's built-in key.
pub fn sums_are_signed(sums: &[u8], signature: &str) -> bool {
    zero_discovery::sign::key_configured() && zero_discovery::sign::verify(sums, signature)
}

/// As [`sums_are_signed`] with an explicit key, for tests.
pub fn sums_are_signed_by(public_key_hex: &str, sums: &[u8], signature: &str) -> bool {
    zero_discovery::sign::verify_with(public_key_hex, sums, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &str = "\
1111111111111111111111111111111111111111111111111111111111111111  ZeroNet-Linux-x64.AppImage
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  ZrayCore-Linux-x64
2222222222222222222222222222222222222222222222222222222222222222 *ZrayCore-Linux-ARM64
3333  short-hash-line
";

    #[test]
    fn the_hash_of_the_right_asset_is_found() {
        assert_eq!(
            expected_hash(SUMS, "ZrayCore-Linux-x64").unwrap(),
            "a".repeat(64)
        );
        assert_eq!(
            expected_hash(SUMS, "ZrayCore-Linux-ARM64").unwrap(),
            "2".repeat(64)
        );
    }

    #[test]
    fn a_missing_or_malformed_entry_is_nothing() {
        assert!(expected_hash(SUMS, "ZrayCore-Linux-riscv").is_none());
        assert!(expected_hash(SUMS, "short-hash-line").is_none());
        assert!(expected_hash("", "x").is_none());
    }

    #[test]
    fn only_a_signature_from_the_trusted_key_is_accepted() {
        let seed = [7u8; 32];
        let public = zero_discovery::sign::public_hex(&seed);
        let signature = zero_discovery::sign::sign_with(&seed, SUMS.as_bytes());
        assert!(sums_are_signed_by(&public, SUMS.as_bytes(), &signature));
        let other = zero_discovery::sign::public_hex(&[8u8; 32]);
        assert!(!sums_are_signed_by(&other, SUMS.as_bytes(), &signature));
        assert!(!sums_are_signed_by(&public, b"changed", &signature));
    }
}
