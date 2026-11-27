//! `zray zerov1`: set up a ZeroV1 server and hand out its links. (The code
//! calls the protocol Tide, the name it was built under.)
//!
//! How this works: a Tide server is an ordinary Zray config with one `tide`
//! inbound. `init` writes that config with fresh keys and random paths, plus
//! a users file holding one first user, and prints what the operator needs:
//! the link and QR code for that user, the address of the control panel, and
//! the command that starts the server. `links` prints the links of an
//! existing server again.
//!
//! The rule it keeps: nothing is overwritten. `init` refuses to run where a
//! config already exists, because that config holds the server's key and
//! every link ever handed out depends on it.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zero_config::{InboundProtocol, TideInboundConfig};
use zero_protocol::tide::{encode_key, generate_keypair};
use zero_runtime::tide_users::{qr_terminal, share_link};

const CONFIG_FILE: &str = "zerov1-server.json";
const USERS_FILE: &str = "zerov1-users.json";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("links") => links(&args[1..]),
        Some("add") => add(&args[1..]),
        _ => bail!(
            "usage: zray zerov1 init --host <domain> (--cert F --key F | --behind-proxy PORT | --reality SITE), \
             zray zerov1 links <config>, or zray zerov1 add <config> <name>"
        ),
    }
}

fn random_hex(bytes: usize) -> String {
    use std::io::Read;
    let mut raw = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut raw))
        .expect("the system's random source is readable");
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Options {
    host: String,
    port: u16,
    listen: String,
    directory: PathBuf,
    name: String,
    certificate: Option<(String, String)>,
    /// Plain HTTP/2 on this local port, for a web server in front.
    behind_proxy: Option<u16>,
    /// Sit behind REALITY instead of a certificate: the real site whose name
    /// clients show (`www.example.com`), and where a prober is sent.
    reality: Option<(String, String)>,
    allow_private: bool,
}

fn parse(args: &[String]) -> Result<Options> {
    let mut options = Options {
        host: String::new(),
        port: 443,
        listen: "0.0.0.0".into(),
        directory: PathBuf::from("."),
        name: "first".into(),
        certificate: None,
        behind_proxy: None,
        reality: None,
        allow_private: false,
    };
    let (mut certificate, mut key) = (None, None);
    let (mut reality, mut target) = (None, None);
    let mut at = 0;
    let value = |at: &mut usize| -> Result<String> {
        *at += 1;
        args.get(*at)
            .cloned()
            .with_context(|| format!("{} needs a value", args[*at - 1]))
    };
    while at < args.len() {
        match args[at].as_str() {
            "--host" => options.host = value(&mut at)?,
            "--port" => options.port = value(&mut at)?.parse().context("--port is not a port")?,
            "--listen" => options.listen = value(&mut at)?,
            "--dir" => options.directory = PathBuf::from(value(&mut at)?),
            "--name" => options.name = value(&mut at)?,
            "--cert" => certificate = Some(value(&mut at)?),
            "--key" => key = Some(value(&mut at)?),
            "--behind-proxy" => {
                options.behind_proxy = Some(
                    value(&mut at)?
                        .parse()
                        .context("--behind-proxy needs a local port")?,
                )
            }
            "--reality" => reality = Some(value(&mut at)?),
            "--target" => target = Some(value(&mut at)?),
            "--allow-private" => options.allow_private = true,
            other => bail!("unknown option {other:?}"),
        }
        at += 1;
    }
    if options.host.is_empty() {
        bail!("--host is required: the domain clients will connect to");
    }
    options.certificate = match (certificate, key) {
        (Some(certificate), Some(key)) => Some((certificate, key)),
        (None, None) => None,
        _ => bail!("--cert and --key go together"),
    };
    if target.is_some() && reality.is_none() {
        bail!("--target only goes with --reality");
    }
    options.reality = reality.map(|name| {
        let target = target.unwrap_or_else(|| format!("{name}:443"));
        (name, target)
    });
    let chosen = [
        options.certificate.is_some(),
        options.behind_proxy.is_some(),
        options.reality.is_some(),
    ];
    if chosen.iter().filter(|set| **set).count() != 1 {
        bail!(
            "choose one: --cert <file> --key <file> to serve TLS here, \
             --behind-proxy <port> to sit behind a web server such as Caddy, or \
             --reality <site> to hide behind REALITY (the host can then be a bare address)"
        );
    }
    Ok(options)
}

fn init(args: &[String]) -> Result<()> {
    let options = parse(args)?;
    std::fs::create_dir_all(&options.directory)
        .with_context(|| format!("creating {}", options.directory.display()))?;
    let directory = options
        .directory
        .canonicalize()
        .with_context(|| format!("resolving {}", options.directory.display()))?;
    let config_path = directory.join(CONFIG_FILE);
    let users_path = directory.join(USERS_FILE);
    if config_path.exists() {
        bail!(
            "{} already exists. It holds this server's key; delete it yourself only if you \
             mean to invalidate every link it handed out.",
            config_path.display()
        );
    }

    let (secret, _) = generate_keypair();
    let mut first_user = [0u8; 16];
    first_user.copy_from_slice(&hex_bytes(&random_hex(16)));
    let path = format!("/static/{}", random_hex(6));
    // Behind REALITY a browser never reaches the server, so there is no panel.
    let admin = options
        .reality
        .is_none()
        .then(|| format!("/manage-{}", random_hex(16)));

    let (listen, port, stream) =
        match (&options.certificate, options.behind_proxy, &options.reality) {
            (Some((certificate, key)), _, _) => (
                options.listen.clone(),
                options.port,
                json!({"security": "tls", "tlsSettings": {"certificates": [{
                    "certificateFile": absolute(certificate)?,
                    "keyFile": absolute(key)?,
                }]}}),
            ),
            (None, Some(local), _) => ("127.0.0.1".to_string(), local, json!({"security": "none"})),
            (None, None, Some((name, target))) => {
                // REALITY's own key pair, apart from the ZeroV1 key.
                let private: [u8; 32] = hex_bytes(&random_hex(32))
                    .try_into()
                    .expect("32 random bytes");
                (
                    options.listen.clone(),
                    options.port,
                    json!({"network": "tcp", "security": "reality", "realitySettings": {
                        "target": target,
                        "serverNames": [name],
                        "privateKey": encode_key(&private),
                        "shortIds": [random_hex(8)],
                    }}),
                )
            }
            (None, None, None) => unreachable!("checked in parse"),
        };
    let mut config = json!({
        "log": {"loglevel": "warning"},
        // The server looks up the names its clients ask for.
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [{
            "tag": "zerov1-in",
            "listen": listen,
            "port": port,
            "protocol": "zerov1",
            "settings": {
                "path": path,
                "secretKey": encode_key(&secret),
                "users": [],
                "usersFile": users_path,
                "publicHost": options.host,
                "publicPort": options.port,
            },
            "streamSettings": stream,
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
    });
    if let Some(admin) = &admin {
        config["inbounds"][0]["settings"]["adminPath"] = json!(admin);
    }
    if !options.allow_private {
        // A client must not be able to reach services on the server's own
        // machine or its private network through the tunnel.
        config["routing"] = json!({
            "domainStrategy": "IPIfNonMatch",
            "rules": [{
                "type": "field",
                "ip": [
                    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
                    "::1/128", "fc00::/7", "fe80::/10",
                ],
                "outboundTag": "block",
            }],
        });
    }
    let users = json!([{"id": encode_key(&first_user), "name": options.name}]);
    write_private(&users_path, &serde_json::to_string_pretty(&users)?)?;
    write_private(&config_path, &serde_json::to_string_pretty(&config)?)?;

    let inbound = tide_inbound(&config_path)?;
    println!("ZeroV1 server set up in {}\n", directory.display());
    print_user(&inbound, &first_user, &options.name);
    match &admin {
        Some(admin) => println!(
            "Control panel (keep this address to yourself, it is the password):\n  https://{}{}{}/\n",
            options.host,
            if options.port == 443 {
                String::new()
            } else {
                format!(":{}", options.port)
            },
            admin
        ),
        None => println!(
            "More users: zray zerov1 add {} <name>, then restart the server.\n",
            config_path.display()
        ),
    }
    println!("Start the server:\n  zray run {}\n", config_path.display());
    // A unit file, so the server starts at boot and comes back if it stops.
    let binary = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .map_or_else(
            || "/usr/local/bin/zray".to_string(),
            |path| path.display().to_string(),
        );
    let unit_path = directory.join("zerov1.service");
    let unit = format!(
        "[Unit]\nDescription=ZeroV1 server (Zray)\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart={binary} run {config}\nRestart=on-failure\nRestartSec=2\n\
         LimitNOFILE=65536\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n",
        config = config_path.display()
    );
    if write_private(&unit_path, &unit).is_ok() {
        println!(
            "To run it as a service that starts at boot:\n  \
             cp {} /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now zerov1\n",
            unit_path.display()
        );
    }
    if let Some((name, target)) = &options.reality {
        println!(
            "It listens on {}:{} behind REALITY. A client that cannot prove itself is passed to\n\
             {target}, so a prober sees {name}. Pick a site that is reachable from the server\n\
             and serves TLS 1.3.\n",
            options.listen, options.port
        );
    }
    if let Some(local) = options.behind_proxy {
        // A web server in front always has the panel (only REALITY has none).
        let admin = admin.as_deref().unwrap_or_default();
        println!(
            "It listens on 127.0.0.1:{local} without TLS, for a web server in front.\n\
             With Caddy, add this inside the site block for {host}, before your own site:\n\n  \
             @tide path {path}/* {admin} {admin}/*\n  \
             reverse_proxy @tide h2c://127.0.0.1:{local} {{\n    flush_interval -1\n  }}\n",
            host = options.host
        );
    }
    Ok(())
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

fn absolute(path: &str) -> Result<String> {
    let resolved = Path::new(path)
        .canonicalize()
        .with_context(|| format!("{path} does not exist"))?;
    Ok(resolved.to_string_lossy().into_owned())
}

/// Write a file only its owner can read: both files hold secrets.
fn write_private(path: &Path, text: &str) -> Result<()> {
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
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))
}

/// The Tide inbound of the config at `path`, as the server itself reads it.
fn tide_inbound(path: &Path) -> Result<TideInboundConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("the config is not JSON")?;
    let (generation, _) = zero_config::compile_config(&value, zero_core::GenerationId(1))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    generation
        .config
        .inbounds
        .iter()
        .find_map(|inbound| match &inbound.protocol {
            InboundProtocol::Tide(tide) => Some(tide.clone()),
            _ => None,
        })
        .context("the config has no zerov1 inbound")
}

fn print_user(inbound: &TideInboundConfig, user: &[u8; 16], name: &str) {
    match share_link(inbound, user, name) {
        Some(link) => {
            println!("User \"{name}\":\n  {link}\n");
            if let Some(code) = qr_terminal(&link) {
                println!("{code}");
            }
        }
        None => println!("User \"{name}\": the config has no publicHost, so there is no link."),
    }
}

/// `add <config> <name>`: another user in the server's users file, with their
/// link. The server reads the file when it starts, so it is restarted after.
fn add(args: &[String]) -> Result<()> {
    let [config, name] = args else {
        bail!("usage: zray zerov1 add <config> <name>");
    };
    let inbound = tide_inbound(Path::new(config))?;
    let file = inbound
        .users_file
        .as_deref()
        .context("the config has no usersFile to add to")?;
    let mut entries: Vec<Value> = match std::fs::read_to_string(file) {
        Ok(text) => serde_json::from_str(&text).context("the users file is not a JSON list")?,
        Err(_) => Vec::new(),
    };
    let mut user = [0u8; 16];
    user.copy_from_slice(&hex_bytes(&random_hex(16)));
    entries.push(json!({"id": encode_key(&user), "name": name}));
    // Replace the file in one step, so a crash cannot leave half a list.
    let temporary = format!("{file}.new");
    let _ = std::fs::remove_file(&temporary);
    write_private(
        Path::new(&temporary),
        &serde_json::to_string_pretty(&entries)?,
    )?;
    std::fs::rename(&temporary, file).with_context(|| format!("replacing {file}"))?;
    print_user(&inbound, &user, name);
    println!("Restart the server so it takes the new user.");
    Ok(())
}

fn links(args: &[String]) -> Result<()> {
    let path = args
        .first()
        .context("links needs the server's config file")?;
    let inbound = tide_inbound(Path::new(path))?;
    let mut users: Vec<([u8; 16], String)> = inbound
        .users
        .iter()
        .map(|user| (user.id, user.name.to_string()))
        .collect();
    if let Some(file) = inbound.users_file.as_deref() {
        if let Ok(text) = std::fs::read_to_string(file) {
            for entry in serde_json::from_str::<Vec<Value>>(&text).unwrap_or_default() {
                let id = entry
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(zero_protocol::tide::decode_key::<16>);
                if let Some(id) = id {
                    let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
                    users.push((id, name.to_string()));
                }
            }
        }
    }
    if users.is_empty() {
        println!("This server has no users yet. Add one in its control panel, or with `zray zerov1 add`.");
    }
    for (id, name) in &users {
        print_user(&inbound, id, name);
    }
    Ok(())
}
