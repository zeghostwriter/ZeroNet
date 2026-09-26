//! `zeronet-sign` — makes and verifies the detached Ed25519 signatures that
//! protect the crowd-data lists (see `zero_discovery::sign`).
//!
//! ```text
//! # Once, by a maintainer: print a fresh key pair.
//! zeronet-sign keygen
//!
//! # In CI: sign a file, writing <file>.sig beside it.
//! #   the 32-byte seed comes from $CROWD_SIGNING_KEY (base64 or hex).
//! zeronet-sign sign verified.txt rankings.json
//!
//! # Anywhere: check a file against a public key (hex).
//! zeronet-sign verify --key <hex> verified.txt
//! ```
//!
//! `keygen` prints the public key (paste it into `sign::PUBLIC_KEY_HEX`) and
//! the private seed (store it as the `CROWD_SIGNING_KEY` secret); the seed is
//! written only to stdout and never to a file.

use std::path::Path;

use zero_discovery::sign;

fn main() {
    if let Err(e) = run() {
        eprintln!("zeronet-sign: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => keygen(),
        Some("sign") => sign_files(args.collect()),
        Some("verify") => verify_file(args.collect()),
        Some(other) => Err(format!("unknown command {other:?}; use keygen, sign or verify")),
        None => Err("a command is required: keygen, sign or verify".into()),
    }
}

/// Print a fresh key pair: public key hex to paste into the app, private
/// seed (base64) to store as a CI secret.
fn keygen() -> Result<(), String> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    use base64::Engine as _;
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    println!("public key (paste into zero_discovery::sign::PUBLIC_KEY_HEX):");
    println!("  {}", sign::public_hex(&seed));
    println!();
    println!("private seed (store as the CROWD_SIGNING_KEY secret; keep it safe, it cannot be recovered):");
    println!("  {secret_b64}");
    Ok(())
}

/// Read the signing seed from `$CROWD_SIGNING_KEY`, accepting base64 or hex.
fn seed_from_env() -> Result<[u8; 32], String> {
    let raw = std::env::var("CROWD_SIGNING_KEY")
        .map_err(|_| "set CROWD_SIGNING_KEY to the signing seed (base64 or hex)".to_string())?;
    let raw = raw.trim();
    // Hex first (64 chars, all hex), else base64.
    let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex_decode(raw)?
    } else {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|e| format!("CROWD_SIGNING_KEY is neither hex nor base64: {e}"))?
    };
    bytes
        .try_into()
        .map_err(|_| "CROWD_SIGNING_KEY must decode to exactly 32 bytes".to_string())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; hex.len() / 2];
    hex::decode_to_slice(hex, &mut out).map_err(|e| format!("bad hex: {e}"))?;
    Ok(out)
}

/// Sign each file, writing `<file>.sig` beside it.
fn sign_files(paths: Vec<String>) -> Result<(), String> {
    if paths.is_empty() {
        return Err("sign needs at least one file".into());
    }
    let seed = seed_from_env()?;
    for path in &paths {
        let body = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let line = sign::sign_with(&seed, &body);
        let sig_path = format!("{path}.sig");
        std::fs::write(&sig_path, format!("{line}\n"))
            .map_err(|e| format!("cannot write {sig_path}: {e}"))?;
        eprintln!("signed {path} -> {sig_path}");
    }
    Ok(())
}

/// Verify a file against `--key <hex>` and its `<file>.sig`.
fn verify_file(args: Vec<String>) -> Result<(), String> {
    let mut key = None;
    let mut file = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key = Some(it.next().ok_or("--key needs a value")?),
            other => file = Some(other.to_string()),
        }
    }
    let key = key.ok_or("--key <hex> is required")?;
    let file = file.ok_or("a file to verify is required")?;
    let body = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let sig_path = format!("{file}.sig");
    let sig = std::fs::read_to_string(&sig_path)
        .map_err(|e| format!("cannot read {sig_path}: {e}"))?;
    if sign::verify_with(&key, &body, &sig) {
        eprintln!("{file}: signature valid");
        Ok(())
    } else {
        let _ = Path::new(&file);
        Err(format!("{file}: signature INVALID"))
    }
}
