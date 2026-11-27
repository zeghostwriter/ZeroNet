//! Keys and identifiers the installer makes on the user's own device.
//!
//! Nothing here is sent anywhere by itself. The SSH key's public half goes to
//! the server's `authorized_keys` so the app can come back without a
//! password; the REALITY public key and the user ids go into the client
//! links; every private half stays where it was made (the device, or for the
//! REALITY key the server's config file).

use base64::Engine as _;
use rand::RngCore;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// `bytes` random bytes as lowercase hex.
pub fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// A random UUID (version 4), the form VLESS wants for a user id.
pub fn new_uuid() -> String {
    let mut b = random::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// A secret for the server's own management API: 256 bits, hex.
pub fn new_token() -> String {
    random_hex(32)
}

/// An SSH key pair in OpenSSH text form.
pub struct SshKey {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` text. Secret: it is the way back
    /// into the user's server, so the apps keep it in private storage only.
    pub private_openssh: String,
    /// One `authorized_keys` line, ending without a newline.
    pub public_openssh: String,
}

/// A new ed25519 key, commented so the user can recognise it on the server.
pub fn new_ssh_key(comment: &str) -> SshKey {
    let seed = random::<32>();
    let keypair = Ed25519Keypair::from_seed(&seed);
    let mut key = PrivateKey::from(keypair);
    key.set_comment(comment);
    let private_openssh = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("an ed25519 key always encodes")
        .to_string();
    let public_openssh = key
        .public_key()
        .to_openssh()
        .expect("a public key always encodes");
    SshKey {
        private_openssh,
        public_openssh,
    }
}

/// The public half of an OpenSSH private key, as an `authorized_keys` line.
pub fn public_of(private_openssh: &str) -> Result<String, String> {
    let key = PrivateKey::from_openssh(private_openssh).map_err(|e| e.to_string())?;
    PublicKey::from(key.public_key().key_data().clone())
        .to_openssh()
        .map_err(|e| e.to_string())
}

/// A REALITY key pair, as Xray prints it: unpadded URL-safe base64 of the raw
/// X25519 private and public keys.
pub struct RealityKeys {
    pub private: String,
    pub public: String,
}

pub fn new_reality_keys() -> RealityKeys {
    let secret = x25519_dalek::StaticSecret::from(random::<32>());
    let public = x25519_dalek::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    RealityKeys {
        private: b64.encode(secret.to_bytes()),
        public: b64.encode(public.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_version_4_and_unique() {
        let (a, b) = (new_uuid(), new_uuid());
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn an_ssh_key_round_trips_and_names_its_comment() {
        let key = new_ssh_key("zray-test");
        assert!(key
            .private_openssh
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
        assert!(key.public_openssh.ends_with("zray-test"));
        let again = public_of(&key.private_openssh).unwrap();
        // The comment is part of the line written at creation, not of the key.
        assert!(key.public_openssh.starts_with(&again));
    }

    #[test]
    fn reality_keys_are_a_matching_x25519_pair() {
        let keys = new_reality_keys();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let private: [u8; 32] = b64.decode(&keys.private).unwrap().try_into().unwrap();
        let public: [u8; 32] = b64.decode(&keys.public).unwrap().try_into().unwrap();
        let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
        assert_eq!(derived.as_bytes(), &public);
        assert_eq!(keys.private.len(), 43);
    }
}
