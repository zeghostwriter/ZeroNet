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
//! # Anywhere: check a file against a public key (hex), by default the one
//! # compiled into this build.
//! zeronet-sign verify [--key <hex>] verified.txt
//!
//! # Does the seed in $CROWD_SIGNING_KEY belong to the key the app trusts?
//! zeronet-sign check
//!
//! # Turn a file of carrier links (one per line) into the TXT records of a
//! # descriptor (see `zero_discovery::rendezvous`): prints `name<TAB>text`
//! # lines, `f0` to `f<count-1>`, for the zone. The epoch is hours since 1970
//! # and must grow with every publish.
//! zeronet-sign descriptor --epoch 493000 [--count 64] carriers.txt
//! ```
//!
//! `keygen` prints the public key (paste it into `sign::PUBLIC_KEY_HEX`) and
//! the private seed (store it as the `CROWD_SIGNING_KEY` secret); the seed is
//! written only to stdout and never to a file.

use std::path::Path;

use zero_discovery::{rendezvous, sign};

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
        Some("check") => check_seed(),
        Some("descriptor") => descriptor(args.collect()),
        Some(other) => Err(format!(
            "unknown command {other:?}; use keygen, sign, verify or check"
        )),
        None => Err("a command is required: keygen, sign, verify or check".into()),
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

/// Say whether the seed in `$CROWD_SIGNING_KEY` is the private half of the
/// public key compiled into this build, without signing or printing anything
/// secret. Run it with the seed you believe is in the CI secret.
fn check_seed() -> Result<(), String> {
    let seed = seed_from_env()?;
    if sign::matches_compiled_key(&seed) {
        eprintln!("This seed matches the public key compiled into the app.");
        Ok(())
    } else {
        Err(format!(
            "This seed does NOT match the compiled public key ({}); its own public key is {}.",
            sign::PUBLIC_KEY_HEX,
            sign::public_hex(&seed)
        ))
    }
}

/// Print the TXT records of a signed descriptor naming the links in a file.
fn descriptor(args: Vec<String>) -> Result<(), String> {
    let (mut epoch, mut count, mut file) = (None, None, None);
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--epoch" => epoch = it.next().and_then(|v| v.parse::<u64>().ok()),
            "--count" => count = it.next().and_then(|v| v.parse::<u32>().ok()),
            other => file = Some(other.to_string()),
        }
    }
    let epoch = epoch.ok_or("--epoch <hours since 1970> is required")?;
    let file = file.ok_or("a file of carrier links is required")?;
    let text = std::fs::read_to_string(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let links: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    let blob = rendezvous::sign_blob(&seed_from_env()?, epoch, &links);
    // Checked the way a client will check it, so a bad file fails here.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 3600);
    let key = sign::public_hex(&seed_from_env()?);
    rendezvous::verify(&blob, &key, 0, now)?;
    // Three times the blocks needed leaves room for names being blocked.
    let count = count.unwrap_or(3 * rendezvous::blocks_for(blob.len()) as u32 + 8);
    for (name, text) in rendezvous::zone_records(&blob, count)? {
        println!("{name}\t{text}");
    }
    eprintln!(
        "{} carriers, epoch {epoch}, {} bytes, {count} records",
        links.len(),
        blob.len()
    );
    Ok(())
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
    // Without --key, the key compiled into this build: the one the app trusts.
    let key = key.unwrap_or_else(|| sign::PUBLIC_KEY_HEX.to_string());
    let file = file.ok_or("a file to verify is required")?;
    let body = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let sig_path = format!("{file}.sig");
    let sig =
        std::fs::read_to_string(&sig_path).map_err(|e| format!("cannot read {sig_path}: {e}"))?;
    if sign::verify_with(&key, &body, &sig) {
        eprintln!("{file}: signature valid");
        Ok(())
    } else {
        let _ = Path::new(&file);
        Err(format!("{file}: signature INVALID"))
    }
}
