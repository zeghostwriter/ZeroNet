//! `zeronet-stats` — the sealed totals of how each connection mode does.
//!
//! ```text
//! zeronet-stats keygen
//! zeronet-stats seal --reports reports.json --public <hex> --out-dir modes [--days 2]
//! zeronet-stats open <file.sealed> [<more.sealed> ...]      (secret in MODE_STATS_SECRET)
//! ```
//!
//! `keygen` is run once, on the maintainer's own computer; it prints a public
//! key for the Action and a secret key to keep out of GitHub. `seal` is run
//! by the `crowd` Action: it turns the relay's mode reports into one sealed
//! file per UTC day and prints only how many reports went into each, never a
//! figure, because the log is public. `open` reads sealed files with the
//! secret key.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use zero_discovery::crowd::Report;
use zero_discovery::modestats;

fn main() {
    if let Err(e) = run() {
        eprintln!("zeronet-stats: {e}");
        std::process::exit(1);
    }
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|_| format!("{what} is not hex"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| format!("{what} must be 32 bytes (64 hex digits)"))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => {
            let (public, secret) = modestats::keygen();
            println!("public: {}", hex::encode(public));
            println!("secret: {}", hex::encode(secret));
            eprintln!("Put the public key in the MODE_STATS_KEY variable. Keep the secret one off GitHub.");
            Ok(())
        }
        Some("seal") => seal(args.collect()),
        Some("open") => open(args.collect()),
        _ => Err("usage: zeronet-stats keygen | seal --reports F --public HEX --out-dir D | open FILE...".into()),
    }
}

fn seal(args: Vec<String>) -> Result<(), String> {
    let (mut reports, mut public, mut out_dir, mut days) = (None, None, None, 2i64);
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--reports" => reports = Some(PathBuf::from(value()?)),
            "--public" => public = Some(value()?),
            "--out-dir" => out_dir = Some(PathBuf::from(value()?)),
            "--days" => days = value()?.parse().map_err(|_| "--days needs a number")?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let reports_path = reports.ok_or("--reports is required")?;
    let public = hex32(&public.ok_or("--public is required")?, "the public key")?;
    let out_dir = out_dir.ok_or("--out-dir is required")?;
    let text = std::fs::read_to_string(&reports_path)
        .map_err(|e| format!("cannot read {}: {e}", reports_path.display()))?;
    let reports: Vec<Report> =
        serde_json::from_str(&text).map_err(|e| format!("reports are not valid JSON: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
    let mut written = 0;
    for back in 0..days.max(1) {
        let start = modestats::day_start(now) - back * 86_400;
        let n = modestats::count(&reports, start);
        if n == 0 {
            continue;
        }
        let summary = modestats::summarize(&reports, start);
        let json = serde_json::to_vec(&summary).map_err(|e| e.to_string())?;
        let sealed = modestats::seal(&public, &json)?;
        let path = out_dir.join(format!("{}.sealed", summary.day));
        std::fs::write(&path, sealed)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        // Only a count: this log is public.
        eprintln!("{}: {n} mode reports sealed", summary.day);
        written += 1;
    }
    eprintln!("{written} sealed file(s) written");
    Ok(())
}

fn open(files: Vec<String>) -> Result<(), String> {
    if files.is_empty() {
        return Err("open needs at least one file".into());
    }
    let secret = std::env::var("MODE_STATS_SECRET").map_err(|_| "MODE_STATS_SECRET is not set")?;
    let secret = hex32(&secret, "the secret key")?;
    for file in files {
        let sealed = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
        let plain = modestats::open(&secret, &sealed).map_err(|e| format!("{file}: {e}"))?;
        let value: serde_json::Value = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}
