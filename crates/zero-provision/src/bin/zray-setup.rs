//! `zray-setup`: the server installer from a terminal, with no app.
//!
//! The apps use the same engine through their menus; this is for scripts and
//! for anyone who prefers a command line.
//!
//! ```text
//! zray-setup fingerprint --host 203.0.113.7
//! ZRAY_SSH_PASSWORD=... zray-setup install --host 203.0.113.7 \
//!     --trust SHA256:... --save my-server.json
//! zray-setup links --record my-server.json
//! zray-setup usage --record my-server.json
//! zray-setup remove --record my-server.json --yes
//! ```
//!
//! The password is read from the environment (never from an argument, which
//! shows up in process listings and shell history).

use std::path::PathBuf;
use std::process::ExitCode;

use zero_provision::install::{self, BinarySource, Event, RealityRequest, Request};
use zero_provision::manage;
use zero_provision::record::ServerRecord;
use zero_provision::ssh::{self, Auth, Login};

const USAGE: &str = "usage:\n  zray-setup fingerprint --host H [--port 22]\n  \
zray-setup install --host H --trust SHA256:.. [--port 22] [--user root] [--key-file F] \
[--name N] [--sni SITE] [--reality-port P] [--no-reality] [--xhttp] [--xhttp-port P] [--zerov1] [--zerov1-port P] [--masterdns-domain t.example.com] [--local-binary FILE] [--release TAG] [--no-key] \
[--save FILE]\n  \
zray-setup links --record FILE\n  zray-setup usage --record FILE\n  \
zray-setup remove --record FILE --yes\n\n\
The SSH password is read from ZRAY_SSH_PASSWORD; a key's passphrase from ZRAY_SSH_KEY_PASSPHRASE.";

struct Args(Vec<String>);

impl Args {
    fn value(&self, name: &str) -> Option<String> {
        let at = self.0.iter().position(|a| a == name)?;
        self.0.get(at + 1).cloned()
    }
    fn flag(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
}

fn load(args: &Args) -> Result<ServerRecord, String> {
    let path = args.value("--record").ok_or("--record FILE is required")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not a server record: {e}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let all: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = all.first().cloned() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let args = Args(all[1..].to_vec());
    match run(&command, &args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: &str, args: &Args) -> Result<(), String> {
    match command {
        "fingerprint" => {
            let host = args.value("--host").ok_or("--host is required")?;
            let port = port(args, "--port", 22)?;
            let key = ssh::fetch_host_key(&host, port)
                .await
                .map_err(|e| e.to_string())?;
            println!("{} ({})", key.fingerprint, key.algorithm);
            Ok(())
        }
        "install" => install_command(args).await,
        "links" => {
            for config in load(args)?.client_configs() {
                show(&config);
            }
            Ok(())
        }
        "usage" => {
            let record = load(args)?;
            let conn = manage::connect(&record).await.map_err(|e| e.to_string())?;
            let usage = manage::usage(&conn, &record)
                .await
                .map_err(|e| e.to_string())?;
            conn.close().await;
            println!("{}", serde_json::to_string_pretty(&usage).unwrap());
            Ok(())
        }
        "check-masterdns" => {
            // `--resolver 8.8.8.8` (repeatable) goes through a public resolver,
            // the real path; `--direct IP` asks the server itself.
            let record = load(args)?;
            let service = record
                .services
                .iter()
                .find_map(|s| match s {
                    zero_provision::record::Service::MasterDns(m) => Some(m.clone()),
                    _ => None,
                })
                .ok_or("this server has no MasterDNS service")?;
            let mut resolvers: Vec<std::net::SocketAddr> = Vec::new();
            let mut at = 0;
            while at < args.0.len() {
                if args.0[at] == "--resolver" || args.0[at] == "--direct" {
                    let text = args.0.get(at + 1).ok_or("a resolver address is needed")?;
                    let text = if text.contains(':') {
                        text.clone()
                    } else {
                        format!("{text}:53")
                    };
                    resolvers.push(
                        text.parse()
                            .map_err(|_| format!("{text} is not an address"))?,
                    );
                    at += 1;
                }
                at += 1;
            }
            for result in zero_provision::probe::probe_masterdns(&service, &resolvers).await {
                println!("{}", serde_json::to_string(&result).unwrap());
            }
            Ok(())
        }
        "remove" => {
            if !args.flag("--yes") {
                return Err("this deletes the server program, its config and the app's access; add --yes to go ahead".into());
            }
            let record = load(args)?;
            let conn = manage::connect(&record).await.map_err(|e| e.to_string())?;
            manage::remove(&conn, &record, &|step| println!("removed: {step:?}"))
                .await
                .map_err(|e| e.to_string())?;
            conn.close().await;
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

fn show(config: &zero_provision::record::ClientConfig) {
    println!("\n{} ({})", config.user, config.service);
    if let Some(link) = &config.link {
        println!("{link}");
    }
    for file in &config.files {
        println!("--- {} ---\n{}", file.name, file.text);
    }
}

fn port(args: &Args, name: &str, default: u16) -> Result<u16, String> {
    match args.value(name) {
        Some(v) => v.parse().map_err(|_| format!("{name} is not a port")),
        None => Ok(default),
    }
}

async fn install_command(args: &Args) -> Result<(), String> {
    let host = args.value("--host").ok_or("--host is required")?;
    let ssh_port = port(args, "--port", 22)?;
    let trust = args
        .value("--trust")
        .ok_or("--trust SHA256:... is required (get it with `zray-setup fingerprint` and compare it with your hosting panel)")?;
    let auth = match args.value("--key-file") {
        Some(file) => Auth::UserKey {
            pem: std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?,
            passphrase: std::env::var("ZRAY_SSH_KEY_PASSPHRASE").ok(),
        },
        None => Auth::Password(
            std::env::var("ZRAY_SSH_PASSWORD")
                .map_err(|_| "set ZRAY_SSH_PASSWORD (or pass --key-file)")?,
        ),
    };
    let login = Login {
        host: host.clone(),
        port: ssh_port,
        user: args.value("--user").unwrap_or_else(|| "root".into()),
        auth,
    };
    let host_key = ssh::HostKey {
        fingerprint: trust,
        algorithm: String::new(),
    };
    let binary = match (args.value("--local-binary"), args.value("--release")) {
        (Some(path), _) => BinarySource::Local(
            std::fs::read(PathBuf::from(&path)).map_err(|e| format!("{path}: {e}"))?,
        ),
        (None, tag) => BinarySource::Release { tag },
    };
    let request = Request {
        name: args.value("--name").unwrap_or_else(|| host.clone()),
        first_user: "Main".into(),
        reality: if args.flag("--no-reality") {
            None
        } else {
            Some(RealityRequest {
                sni: args
                    .value("--sni")
                    .unwrap_or_else(|| "www.microsoft.com".into()),
                port: match args.value("--reality-port") {
                    Some(p) => Some(p.parse().map_err(|_| "--reality-port is not a port")?),
                    None => None,
                },
            })
        },
        xhttp: if args.flag("--xhttp") {
            Some(install::XhttpRequest {
                sni: args
                    .value("--sni")
                    .unwrap_or_else(|| "www.microsoft.com".into()),
                port: match args.value("--xhttp-port") {
                    Some(p) => Some(p.parse().map_err(|_| "--xhttp-port is not a port")?),
                    None => None,
                },
            })
        } else {
            None
        },
        zerov1: if args.flag("--zerov1") {
            Some(install::Zerov1Request {
                sni: args
                    .value("--sni")
                    .unwrap_or_else(|| "www.microsoft.com".into()),
                port: match args.value("--zerov1-port") {
                    Some(p) => Some(p.parse().map_err(|_| "--zerov1-port is not a port")?),
                    None => None,
                },
            })
        } else {
            None
        },
        masterdns: args
            .value("--masterdns-domain")
            .map(|domain| install::MasterDnsRequest { domain }),
        binary,
        keep_access: !args.flag("--no-key"),
    };
    let outcome = install::install(&login, &host_key, &request, &|event| match event {
        Event::Step {
            step,
            preset,
            number,
            of,
        } => match preset {
            Some(preset) => println!("[{number}/{of}] {step:?} ({preset:?})"),
            None => println!("[{number}/{of}] {step:?}"),
        },
        Event::Detail(text) => println!("      {text}"),
    })
    .await
    .map_err(|e| e.to_string())?;
    for note in &outcome.notes {
        println!("note: {note:?}");
    }
    if let Some(path) = args.value("--save") {
        let text = serde_json::to_string_pretty(&outcome.record).unwrap();
        std::fs::write(&path, text).map_err(|e| format!("{path}: {e}"))?;
        println!("saved {path}");
    }
    for config in outcome.record.client_configs() {
        show(&config);
    }
    Ok(())
}
