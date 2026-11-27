//! Key, id and certificate tools, with the names and output of Xray's own
//! (`uuid`, `x25519`, `wg`, `mldsa65`, `mlkem768`, `vlessenc`, `tls ...`), so
//! scripts and guides written for Xray work unchanged.
//!
//! How this works: each tool is a small function that returns the lines it
//! prints, so the output is testable without a terminal. Keys are written the
//! way Xray writes them: base64url without padding for REALITY and VLESS
//! encryption, standard base64 for WireGuard. `Hash32` is the BLAKE3 hash of
//! the public key, the value a VLESS encryption client pins.
//!
//! The rule: a tool given `-i` is deterministic. The same private key or seed
//! always gives the same public half, so a key can be recovered from what was
//! saved.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey768, MlKem768};
use rand::RngCore;

/// Dispatch a tool by name. `None` when `name` is not one of them.
pub fn run(name: &str, args: &[String]) -> Option<Result<()>> {
    let lines = match name {
        "uuid" => uuid(args),
        "x25519" => x25519(args),
        "wg" => wireguard(args),
        "mldsa65" => mldsa65(args),
        "mlkem768" => mlkem768(args),
        "vlessenc" => Ok(vless_encryption()),
        "tls" => return Some(tls(args)),
        _ => return None,
    };
    Some(lines.map(|lines| {
        for line in lines {
            println!("{line}");
        }
    }))
}

/// The value after `-i` (or `-i=value`), if given.
fn input(args: &[String]) -> Result<Option<String>> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "-i" || arg == "--i" || arg == "-input" {
            return Ok(Some(
                args.next()
                    .ok_or_else(|| anyhow!("{arg} needs a value"))?
                    .clone(),
            ));
        }
        if let Some(value) = arg.strip_prefix("-i=") {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_exact<const N: usize>(
    text: &str,
    engine: &impl base64::Engine,
    what: &str,
) -> Result<[u8; N]> {
    engine
        .decode(text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow!("{what} must be {N} bytes of base64"))
}

// ------------------------------------------------------------------- uuid

/// A random UUIDv4, or with `-i text` the UUIDv5 of that text (at most 30
/// bytes) under the nil namespace, which is how Xray turns a memorable
/// string into a VLESS id.
fn uuid(args: &[String]) -> Result<Vec<String>> {
    let id = match input(args)?.filter(|text| !text.is_empty()) {
        None => uuid::Uuid::new_v4(),
        Some(text) if text.len() > 30 => bail!("Input must be within 30 bytes."),
        Some(text) => uuid::Uuid::new_v5(&uuid::Uuid::nil(), text.as_bytes()),
    };
    Ok(vec![id.to_string()])
}

// ----------------------------------------------------------------- x25519

fn clamp(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

fn key_pair_lines(private: [u8; 32], engine: &impl base64::Engine) -> Vec<String> {
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    vec![
        format!("PrivateKey: {}", engine.encode(private)),
        format!("Password (PublicKey): {}", engine.encode(public.as_bytes())),
        format!(
            "Hash32: {}",
            engine.encode(blake3::hash(public.as_bytes()).as_bytes())
        ),
    ]
}

/// An X25519 key pair for REALITY and VLESS encryption (base64url).
fn x25519(args: &[String]) -> Result<Vec<String>> {
    let std = args.iter().any(|arg| arg == "--std-encoding");
    let private = match input(args)? {
        Some(text) => {
            if std {
                decode_exact::<32>(&text, &STANDARD, "private key")?
            } else {
                decode_exact::<32>(&text, &URL_SAFE_NO_PAD, "private key")?
            }
        }
        None => clamp(random()),
    };
    Ok(if std {
        key_pair_lines(private, &STANDARD)
    } else {
        key_pair_lines(private, &URL_SAFE_NO_PAD)
    })
}

/// An X25519 key pair for WireGuard (standard base64).
fn wireguard(args: &[String]) -> Result<Vec<String>> {
    let private = match input(args)? {
        Some(text) => decode_exact::<32>(&text, &STANDARD, "private key")?,
        None => clamp(random()),
    };
    Ok(key_pair_lines(private, &STANDARD))
}

// ---------------------------------------------------------------- post-quantum

fn mldsa65_verify_key(seed: [u8; 32]) -> Vec<u8> {
    let signing = SigningKey::<MlDsa65>::from_seed(&seed.into());
    signing.verifying_key().encode().as_slice().to_vec()
}

/// An ML-DSA-65 key pair for REALITY's post-quantum signature: the seed
/// goes on the server (`mldsa65Seed`), the verify key on clients
/// (`mldsa65Verify`).
fn mldsa65(args: &[String]) -> Result<Vec<String>> {
    let seed = match input(args)? {
        Some(text) => decode_exact::<32>(&text, &URL_SAFE_NO_PAD, "seed")?,
        None => random(),
    };
    let verify = mldsa65_verify_key(seed);
    Ok(vec![
        format!("Seed: {}", url(&seed)),
        format!("Verify: {}", url(&verify)),
        format!("Hash32: {}", url(blake3::hash(&verify).as_bytes())),
    ])
}

fn mlkem768_client_key(seed: [u8; 64]) -> Vec<u8> {
    let key = DecapsulationKey768::from_seed(seed.into());
    key.encapsulation_key().to_bytes().as_slice().to_vec()
}

/// An ML-KEM-768 key pair for VLESS encryption: the 64-byte seed stays on
/// the server, the encapsulation key ("Client") goes into clients' links.
fn mlkem768(args: &[String]) -> Result<Vec<String>> {
    let seed = match input(args)? {
        Some(text) => decode_exact::<64>(&text, &URL_SAFE_NO_PAD, "seed")?,
        None => random(),
    };
    let client = mlkem768_client_key(seed);
    Ok(vec![
        format!("Seed: {}", url(&seed)),
        format!("Client: {}", url(&client)),
        format!("Hash32: {}", url(blake3::hash(&client).as_bytes())),
    ])
}

/// The `decryption` (server) and `encryption` (client) strings for VLESS
/// encryption, once with X25519 authentication and once with ML-KEM-768.
/// Both exchange keys with ML-KEM-768 anyway; the choice is only how the
/// server proves who it is. Use one, not both.
fn vless_encryption() -> Vec<String> {
    let private = clamp(random());
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let seed: [u8; 64] = random();
    let client = mlkem768_client_key(seed);
    let pair = |private: &[u8], public: &[u8]| {
        [
            format!(
                "\"decryption\": \"mlkem768x25519plus.native.600s.{}\"",
                url(private)
            ),
            format!(
                "\"encryption\": \"mlkem768x25519plus.native.0rtt.{}\"",
                url(public)
            ),
        ]
    };
    let mut lines = vec![
        "Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.".to_string(),
        String::new(),
        "Authentication: X25519, not Post-Quantum".to_string(),
    ];
    lines.extend(pair(&private, public.as_bytes()));
    lines.push(String::new());
    lines.push("Authentication: ML-KEM-768, Post-Quantum".to_string());
    lines.extend(pair(&seed, &client));
    lines
}

/// Whether `MlKem768` is the parameter set the VLESS encryption code speaks;
/// referenced so a change of the library's default shows up here as an error.
#[allow(dead_code)]
type VlessKem = MlKem768;

// --------------------------------------------------------------------- tls

fn tls(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("ping") => tls_ping(&args[1..]),
        Some("hash") => tls_hash(&args[1..]),
        Some("cert") => tls_cert(&args[1..]),
        _ => bail!("usage: zray tls ping [-ip <ip>] <domain> | hash --cert <file> | cert [--ca] [--domain=D] [--expire=240h] [--file=F] [--json]"),
    }
}

/// `--name=value`, `-name=value`, or `--name value`.
fn flag(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let bare = arg.trim_start_matches('-');
        if let Some(value) = bare
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value.to_string());
        }
        if bare == name && arg.starts_with('-') {
            return iter.next().cloned();
        }
    }
    None
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg.trim_start_matches('-') == name)
}

/// SHA-256 of a DER certificate as lower-case hex: the value a client pins
/// with `pinnedPeerCertSha256`.
fn cert_sha256(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(der))
}

fn pem_certificates(text: &[u8]) -> Result<Vec<Vec<u8>>> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<Vec<u8>> = rustls_pki_types::CertificateDer::pem_slice_iter(text)
        .map(|cert| cert.map(|der| der.as_ref().to_vec()))
        .collect::<Result<_, _>>()
        .map_err(|error| anyhow!("reading certificates: {error}"))?;
    if certs.is_empty() {
        bail!("no certificate found");
    }
    Ok(certs)
}

/// `tls hash --cert file`: the SHA-256 of the leaf certificate, and of the
/// others in the file, for `pinnedPeerCertSha256`.
fn tls_hash(args: &[String]) -> Result<()> {
    let path =
        flag(args, "cert").ok_or_else(|| anyhow!("usage: zray tls hash --cert <cert.pem>"))?;
    let text = std::fs::read(&path).with_context(|| format!("open {path}"))?;
    let certs = pem_certificates(&text)?;
    println!("Leaf SHA256:  {}", cert_sha256(&certs[0]));
    for (index, cert) in certs.iter().enumerate().skip(1) {
        println!("CA  #{index} SHA256:  {}", cert_sha256(cert));
    }
    Ok(())
}

/// `tls ping domain`: handshake with the domain (optionally at a given IP) and
/// say what came back: protocol, cipher, ALPN, the certificate chain and the
/// hash to pin. Useful to see what a censor-facing host really answers with.
fn tls_ping(args: &[String]) -> Result<()> {
    let ip = flag(args, "ip");
    let domain = args
        .iter()
        .rev()
        .find(|arg| !arg.starts_with('-') && Some(arg.as_str()) != ip.as_deref())
        .ok_or_else(|| anyhow!("usage: zray tls ping [-ip <ip>] <domain>"))?
        .clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        use tokio::net::{lookup_host, TcpStream};
        let address = match &ip {
            Some(ip) => format!("{ip}:443")
                .parse()
                .context("-ip is not an IP address")?,
            None => lookup_host((domain.as_str(), 443))
                .await
                .with_context(|| format!("resolving {domain}"))?
                .next()
                .ok_or_else(|| anyhow!("{domain} has no address"))?,
        };
        println!("Pinging {domain} at {address}");
        let started = std::time::Instant::now();
        let tcp = TcpStream::connect(address).await.context("connect")?;
        println!("TCP connected in {} ms", started.elapsed().as_millis());
        let params =
            zero_security::tls::TlsParams::new(domain.clone()).with_alpn(&["h2", "http/1.1"]);
        let started = std::time::Instant::now();
        let stream = zero_security::tls::connect(tcp, &params)
            .await
            .map_err(|failure| anyhow!("TLS handshake failed: {failure}"))?;
        println!("TLS handshake in {} ms", started.elapsed().as_millis());
        let (_, session) = stream.get_ref();
        if let Some(version) = session.protocol_version() {
            println!("Version: {version:?}");
        }
        if let Some(suite) = session.negotiated_cipher_suite() {
            println!("Cipher: {:?}", suite.suite());
        }
        if let Some(alpn) = session.alpn_protocol() {
            println!("ALPN: {}", String::from_utf8_lossy(alpn));
        }
        for (index, cert) in session
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            describe_certificate(index, cert.as_ref());
        }
        Ok(())
    })
}

fn describe_certificate(index: usize, der: &[u8]) {
    let role = if index == 0 { "Leaf" } else { "Chain" };
    println!("{role} #{index}: SHA256 {}", cert_sha256(der));
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
        println!("  Subject:  {}", cert.subject());
        println!("  Issuer:   {}", cert.issuer());
        println!(
            "  Valid:    {} to {}",
            cert.validity().not_before,
            cert.validity().not_after
        );
        if let Ok(Some(names)) = cert.subject_alternative_name() {
            let names: Vec<String> = names
                .value
                .general_names
                .iter()
                .map(|name| name.to_string())
                .collect();
            println!("  Names:    {}", names.join(", "));
        }
    }
}

/// `tls cert`: a fresh self-signed certificate and key (a CA with `--ca`),
/// printed as JSON for a config, or saved as `<file>.crt` and `<file>.key`.
fn tls_cert(args: &[String]) -> Result<()> {
    let domain = flag(args, "domain");
    let common_name = flag(args, "name").unwrap_or_else(|| "Zray Inc".to_string());
    let org = flag(args, "org").unwrap_or_else(|| "Zray Inc".to_string());
    let expire = flag(args, "expire")
        .map(|text| parse_duration(&text))
        .transpose()?
        .unwrap_or(std::time::Duration::from_secs(90 * 24 * 3600));
    let ca = has(args, "ca");

    let mut params = rcgen::CertificateParams::new(domain.iter().cloned().collect::<Vec<_>>())
        .context("the domain is not a valid certificate name")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, org);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(3600)).into();
    params.not_after = (now + expire).into();
    if ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
    } else {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    }
    let key = rcgen::KeyPair::generate().context("generating a key")?;
    let cert = params
        .self_signed(&key)
        .context("signing the certificate")?;
    let (cert_pem, key_pem) = (cert.pem(), key.serialize_pem());

    if let Some(path) = flag(args, "file") {
        let (crt, keyfile) = (format!("{path}.crt"), format!("{path}.key"));
        for file in [&crt, &keyfile] {
            if std::path::Path::new(file).exists() {
                bail!("{file} already exists; remove it first");
            }
        }
        std::fs::write(&crt, &cert_pem).with_context(|| format!("writing {crt}"))?;
        write_private(&keyfile, key_pem.as_bytes())?;
        println!("Wrote {crt} and {keyfile}");
    }
    if has(args, "json") || flag(args, "file").is_none() {
        let lines = |pem: &str| -> Vec<String> { pem.lines().map(str::to_string).collect() };
        let out = serde_json::json!({ "certificate": lines(&cert_pem), "key": lines(&key_pem) });
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

/// Write a private key readable by its owner only.
fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .with_context(|| format!("writing {path}"))
}

/// `240h`, `90m`, `30s`, `7d`, or a bare number of hours.
fn parse_duration(text: &str) -> Result<std::time::Duration> {
    let text = text.trim();
    let (number, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let number: u64 = number
        .parse()
        .map_err(|_| anyhow!("{text:?} is not a duration like 240h"))?;
    let seconds = match unit {
        "" | "h" => number * 3600,
        "d" => number * 86_400,
        "m" => number * 60,
        "s" => number,
        _ => bail!("{text:?} is not a duration like 240h"),
    };
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // Vectors produced by Xray 26.3.27 (`xray x25519 -i ...` and friends).

    #[test]
    fn x25519_from_a_private_key_matches_xray() {
        let lines = x25519(&args(&[
            "-i",
            "OJuHKBvwauYfdmzwRceqUOt77wpp6s4F0Nsm6ySqWFk",
        ]))
        .unwrap();
        assert_eq!(
            lines,
            [
                "PrivateKey: OJuHKBvwauYfdmzwRceqUOt77wpp6s4F0Nsm6ySqWFk",
                "Password (PublicKey): 7suroc2UNkMnyhWAv3k8PhY33mTFzBNhK1CLOv8-vyc",
                "Hash32: qGMiAV7Qf8E9Kk7baPKXS2t8vac04BF6QLjIFIkXmPI",
            ]
        );
    }

    #[test]
    fn wireguard_from_a_private_key_matches_xray() {
        let lines = wireguard(&args(&[
            "-i",
            "QIAjjCxkRyHEmv+NA6cJtDMT54k/5XykWe6YZLCJa28=",
        ]))
        .unwrap();
        assert_eq!(
            lines[1],
            "Password (PublicKey): DwbohATlBUtTL1YnJPt8WKPcqWJtg7g/EuIMJFi+LGw="
        );
        assert_eq!(
            lines[2],
            "Hash32: GM5lm8vKu91s+ltsztGStoIPJ/vEiR1td4CTZRFrTEY="
        );
    }

    #[test]
    fn uuid_from_text_is_the_v5_xray_makes() {
        assert_eq!(
            uuid(&args(&["-i", "test"])).unwrap(),
            ["e8b764da-5fe5-51ed-8af8-c5c6eca28d7a"]
        );
        assert_eq!(
            uuid(&args(&["-i", "example"])).unwrap(),
            ["feb54431-301b-52bb-a6dd-e1e93e81bb9e"]
        );
        assert!(uuid(&args(&["-i", &"x".repeat(31)])).is_err());
        let random = uuid(&[]).unwrap();
        assert_eq!(random[0].len(), 36);
        assert_ne!(random, uuid(&[]).unwrap());
    }

    #[test]
    fn mldsa65_and_mlkem768_are_deterministic_from_their_seed() {
        let lines = mldsa65(&args(&[
            "-i",
            "EzUg9vfmX8OXKaNspXhMWPNLu5DxkUDV5kxsuUq5yyY",
        ]))
        .unwrap();
        assert!(lines[1].starts_with("Verify: HGncNTTVmGm5tU5o_ZCOwvBQLuglwG_yPDRLr_8azCu7"));
        let seed = "Yp5pZgh9H-4ejuQ2bQb77pFL9fhuzFaXaHXrEB8_jH07n1B5CZ8i5y84ExjI7cf0U3mjTc_JThqOBCh-kTBpsg";
        let lines = mlkem768(&args(&["-i", seed])).unwrap();
        assert!(lines[1]
            .starts_with("Client: nEgtNPC0v1qJYfkUo4fKq3pV66APP9M3AAHLo1WRYtXB22wwgiLOgcBz"));
        assert_eq!(
            lines[2],
            "Hash32: qc24NgGuULUU4o8vRn-jSHrfEmgqcCmq6Hd2_AZu2_g"
        );
    }

    #[test]
    fn a_wrong_sized_key_is_refused() {
        assert!(x25519(&args(&["-i", "AAAA"])).is_err());
        assert!(mlkem768(&args(&["-i", "AAAA"])).is_err());
        assert!(mldsa65(&args(&["-i", "AAAA"])).is_err());
    }

    #[test]
    fn a_random_x25519_key_is_clamped_and_recoverable() {
        let first = x25519(&[]).unwrap();
        let private = first[0].strip_prefix("PrivateKey: ").unwrap().to_string();
        let again = x25519(&args(&["-i", &private])).unwrap();
        assert_eq!(first, again);
        let bytes = URL_SAFE_NO_PAD.decode(private).unwrap();
        assert_eq!(bytes[0] & 7, 0);
        assert_eq!(bytes[31] & 0xc0, 0x40);
    }

    /// The strings the generator prints must be ones the VLESS encryption
    /// code accepts, for both the client and the server side.
    #[test]
    fn vlessenc_output_is_accepted_by_the_vless_encryption_parser() {
        let lines = vless_encryption();
        let encryptions: Vec<&str> = lines
            .iter()
            .filter_map(|line| line.strip_prefix("\"encryption\": \""))
            .map(|rest| rest.trim_end_matches('"'))
            .collect();
        assert_eq!(encryptions.len(), 2);
        for encryption in encryptions {
            assert!(
                zero_protocol::vless_encryption::is_valid(encryption),
                "{encryption}"
            );
        }
    }

    #[test]
    fn durations_read_like_xrays() {
        assert_eq!(parse_duration("240h").unwrap().as_secs(), 240 * 3600);
        assert_eq!(parse_duration("2d").unwrap().as_secs(), 172_800);
        assert_eq!(parse_duration("90m").unwrap().as_secs(), 5400);
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn a_pem_certificate_is_hashed_like_xrays_tls_hash() {
        // The certificate `xray tls cert` produced for the test, with the
        // hash `xray tls hash` printed for it.
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBgTCCASegAwIBAgIQa66THZO367Xx8hMiH7117TAKBggqhkjOPQQDAjAbMQww\nCgYDVQQKEwNPcmcxCzAJBgNVBAMTAmV4MB4XDTI2MTAxNDA5NDYyNloXDTI3MDEx\nMjEwNDYyNlowGzEMMAoGA1UEChMDT3JnMQswCQYDVQQDEwJleDBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEaq6iug09kuUeNB+ppcpOa9GlAVHGWhmnh096RDxJ2i\npSqqwBTCGIcRjllQj3FD//y4gj+6HYroCfYZX6AKyMijTTBLMA4GA1UdDwEB/wQE\nAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBYGA1UdEQQP\nMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIDyF1NhdKfcDetCiEgNo\ntCXUXfEkFURspLR/KtX5deQzAiEAn3mvXZugTRBhUpUG0XonOGgm/N5jjo6eNPW6\nZG+FJWc=\n-----END CERTIFICATE-----\n";
        let certs = pem_certificates(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(
            cert_sha256(&certs[0]),
            "f98e2cd6dcefd6be3751f540600f9be433d18f6b927021ae53d0ae09a674cb3e"
        );
        assert!(pem_certificates(b"nothing").is_err());
    }
}
