//! Detached Ed25519 signatures for the lists the app trusts.
//!
//! `verified.txt` (the tested server list) and `rankings.json` (which
//! servers work on which network) are fetched over a censored, filtered
//! link where a CDN or a network in the middle could serve a substitute.
//! `verified.txt` is the graver risk: it can introduce servers the app has
//! never seen, so a forged one could steer users onto an attacker's relay.
//!
//! So each file is signed in CI with a key whose public half is compiled
//! into the app ([`PUBLIC_KEY_HEX`]), and the app rejects a body whose
//! signature does not verify. The signature is published beside the file as
//! `<name>.sig`: a single line, `ed25519:<hex>`, so a plain `.txt`/`.json`
//! stays readable and older clients that do not know about signatures keep
//! working (the check is best-effort until a key is set — see the app).
//!
//! The private key never leaves CI: the `create signing key` workflow
//! prints a fresh key pair once, the public half is pasted here and the
//! private half stored as the `CROWD_SIGNING_KEY` secret.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// The public key list bodies are verified against, hex-encoded (32 bytes,
/// 64 hex chars). Set by the maintainer from the `create crowd signing key`
/// workflow; the matching private seed is the `CROWD_SIGNING_KEY` secret CI
/// signs with. While empty, [`verify`] rejects everything, so the app treats
/// "no key compiled in" ([`key_configured`] is false) as "do not verify"
/// rather than "reject" (see `Crowd`/discovery), which keeps a keyless build
/// connecting.
pub const PUBLIC_KEY_HEX: &str =
    "1d2375dcc22a761d95ab5005f576d4673738e128a37f60b68660417ea086e9e8";

/// Line prefix of a detached signature file.
const PREFIX: &str = "ed25519:";

/// Parse a 64-character hex string into 32 bytes.
fn hex32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex, &mut out).ok()?;
    Some(out)
}

/// Parse a 128-character hex string into a 64-byte signature.
fn hex64(hex: &str) -> Option<[u8; 64]> {
    let hex = hex.trim();
    if hex.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    hex::decode_to_slice(hex, &mut out).ok()?;
    Some(out)
}

/// Whether a compiled-in public key is present. When false the app should
/// skip verification rather than reject, so a build without a key still
/// connects.
pub fn key_configured() -> bool {
    !PUBLIC_KEY_HEX.trim().is_empty()
}

/// Verify `signature` (an `ed25519:<hex>` line) over `body` against
/// `public_key_hex`. Returns false on any malformed input, so a caller can
/// treat "does not verify" and "cannot parse" alike.
pub fn verify_with(public_key_hex: &str, body: &[u8], signature: &str) -> bool {
    let Some(key_bytes) = hex32(public_key_hex) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Some(hex) = signature.trim().strip_prefix(PREFIX) else {
        return false;
    };
    let Some(sig_bytes) = hex64(hex) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify(body, &sig).is_ok()
}

/// Verify `signature` over `body` against the compiled-in [`PUBLIC_KEY_HEX`].
pub fn verify(body: &[u8], signature: &str) -> bool {
    verify_with(PUBLIC_KEY_HEX, body, signature)
}

/// Sign `body` with the 32-byte Ed25519 seed `secret`, returning the
/// `ed25519:<hex>` line to publish. Used by the `zeronet-sign` CLI in CI.
pub fn sign_with(secret: &[u8; 32], body: &[u8]) -> String {
    let key = SigningKey::from_bytes(secret);
    let signature = key.sign(body);
    format!("{PREFIX}{}", hex::encode(signature.to_bytes()))
}

/// The public key (hex) matching a 32-byte signing seed, to paste into
/// [`PUBLIC_KEY_HEX`].
pub fn public_hex(secret: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        // Fixed, so the test is deterministic; never a real key.
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn a_signature_verifies_against_its_key() {
        let secret = seed();
        let public = public_hex(&secret);
        let body = b"vless://one\nvless://two\n";
        let sig = sign_with(&secret, body);
        assert!(sig.starts_with("ed25519:"));
        assert!(verify_with(&public, body, &sig));
    }

    #[test]
    fn a_tampered_body_fails() {
        let secret = seed();
        let public = public_hex(&secret);
        let sig = sign_with(&secret, b"the original body\n");
        assert!(!verify_with(&public, b"a different body\n", &sig));
    }

    #[test]
    fn a_wrong_key_fails() {
        let secret = seed();
        let mut other = seed();
        other[0] ^= 0xff;
        let sig = sign_with(&secret, b"body\n");
        assert!(!verify_with(&public_hex(&other), b"body\n", &sig));
    }

    #[test]
    fn malformed_input_is_rejected_not_panicked() {
        let public = public_hex(&seed());
        assert!(!verify_with(&public, b"body", "not-a-signature"));
        assert!(!verify_with(&public, b"body", "ed25519:zz"));
        assert!(!verify_with("", b"body", "ed25519:00"));
        assert!(!verify_with("short", b"body", "ed25519:00"));
    }

    #[test]
    fn a_compiled_key_is_present_and_enforced() {
        // A real key is compiled in, so verification is active: a garbage
        // signature over the built-in key is rejected (it is not skipped).
        assert!(key_configured());
        assert!(!verify(b"anything", "ed25519:00"));
        assert!(!verify(b"anything", "not-a-signature"));
    }

    #[test]
    fn the_compiled_key_is_a_valid_point() {
        // The pasted PUBLIC_KEY_HEX must decode to a usable verifying key,
        // or every signed feed would be refused on devices in the field.
        let key = hex32(PUBLIC_KEY_HEX).expect("PUBLIC_KEY_HEX is 32 hex bytes");
        assert!(VerifyingKey::from_bytes(&key).is_ok());
    }
}
