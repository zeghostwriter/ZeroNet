//! The "My server" page's work: SSH, installing, reading usage, saving.
//!
//! `zeronet_tui::servers` decides what should happen and returns [`Effect`]s;
//! this file runs each on a Tokio task and sends the answer back as a
//! [`BgEvent::Server`], so the screen never waits on the network. The records
//! (which hold the app's SSH key for each server) are stored in the same
//! owner-only database as the rest of the app's data.

use super::*;
use app_tasks::BgEvent;
use std::net::SocketAddr;
use zero_provision::{install, manage, probe, ssh};
use zeronet_tui::servers::{DnsStatus, Effect, Event, ServersState, STORE_KEY};

/// Public resolvers asked when checking that a domain's records spread.
const CHECK_RESOLVERS: [([u8; 4], u16); 3] =
    [([8, 8, 8, 8], 53), ([9, 9, 9, 9], 53), ([1, 1, 1, 1], 53)];

impl App<'_> {
    /// The saved list, read once at start.
    pub(crate) fn load_servers(db: &Database) -> ServersState {
        ServersState::load(db.get_value(STORE_KEY).as_deref())
    }

    /// Run what the page asked for.
    pub(crate) fn run_server_effects(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            self.dirty = true;
            let tx = self.bg.tx.clone();
            let send = move |event: Event| {
                let _ = tx.send(BgEvent::Server(event));
            };
            match effect {
                Effect::FetchHostKey { host, port } => {
                    tokio::spawn(async move {
                        let result = ssh::fetch_host_key(&host, port).await;
                        send(Event::HostKey(result.map_err(|e| e.to_string())));
                    });
                }
                Effect::CheckDns { ns_host, server } => {
                    tokio::spawn(async move {
                        let status = match server.parse::<std::net::IpAddr>() {
                            Err(_) => DnsStatus::Unknown,
                            Ok(ip) => {
                                let resolvers: Vec<SocketAddr> = CHECK_RESOLVERS
                                    .iter()
                                    .map(|(ip, port)| SocketAddr::from((*ip, *port)))
                                    .collect();
                                match probe::ns_host_points_here(&ns_host, ip, &resolvers).await {
                                    Some(true) => DnsStatus::Right,
                                    Some(false) => DnsStatus::Wrong,
                                    None => DnsStatus::Unknown,
                                }
                            }
                        };
                        send(Event::Dns(status));
                    });
                }
                Effect::Install(mut job) => {
                    // `ZRAY_SERVER_BINARY=/path/to/zray` installs that program
                    // instead of the signed release (for offline use and for
                    // testing); the result then says it was not verified.
                    if let Some(path) = std::env::var_os("ZRAY_SERVER_BINARY") {
                        match std::fs::read(&path) {
                            Ok(bytes) => job.request.binary = install::BinarySource::Local(bytes),
                            Err(e) => {
                                self.toasts.error(format!("ZRAY_SERVER_BINARY: {e}"));
                                continue;
                            }
                        }
                    }
                    tokio::spawn(async move {
                        let progress = send.clone();
                        let result = install::install(
                            &job.login,
                            &job.host_key,
                            &job.request,
                            &move |event| progress(Event::Install(event)),
                        )
                        .await;
                        send(Event::Installed(
                            result.map(Box::new).map_err(|e| e.to_string()),
                        ));
                    });
                }
                Effect::Usage { id } => {
                    let Some(record) = self.servers.record(&id).cloned() else {
                        continue;
                    };
                    tokio::spawn(async move {
                        let result = async {
                            let conn = manage::connect(&record).await.map_err(|e| e.to_string())?;
                            let usage = manage::usage(&conn, &record)
                                .await
                                .map_err(|e| e.to_string());
                            conn.close().await;
                            usage
                        }
                        .await;
                        send(Event::Usage(id, result));
                    });
                }
                Effect::Remove { id } => {
                    let Some(record) = self.servers.record(&id).cloned() else {
                        continue;
                    };
                    tokio::spawn(async move {
                        let result = async {
                            let conn = manage::connect(&record).await.map_err(|e| e.to_string())?;
                            let done = manage::remove(&conn, &record, &|_| {}).await;
                            conn.close().await;
                            done.map_err(|e| e.to_string())
                        }
                        .await;
                        send(Event::Removed(id, result));
                    });
                }
                Effect::Save => {
                    if let Err(e) = self.db.set_value(STORE_KEY, &self.servers.to_json()) {
                        self.toasts
                            .error(format!("Could not save your servers: {e}"));
                    }
                }
                Effect::Copy(text) => self.copy_to_clipboard(&text, "Copied"),
                Effect::SaveFiles { id } => self.save_server_files(&id),
                Effect::Probe { id } => {
                    let Some(service) = self.servers.record(&id).and_then(|r| {
                        r.services.iter().find_map(|s| match s {
                            zero_provision::record::Service::MasterDns(m) => Some(m.clone()),
                            _ => None,
                        })
                    }) else {
                        continue;
                    };
                    tokio::spawn(async move {
                        let resolvers: Vec<SocketAddr> = CHECK_RESOLVERS
                            .iter()
                            .map(|(ip, port)| SocketAddr::from((*ip, *port)))
                            .collect();
                        let results = probe::probe_masterdns(&service, &resolvers).await;
                        let answered = results.iter().filter(|r| r.answered).count();
                        let best = results.iter().filter_map(|r| r.millis).min();
                        let text = match (answered, best) {
                            (0, _) => "MasterDNS did not answer through any public resolver. Check that the two DNS records are right and wait a few minutes.".to_string(),
                            (n, Some(ms)) => format!(
                                "MasterDNS works: {n} of {} resolvers reached it (best {ms} ms).",
                                results.len()
                            ),
                            (n, None) => format!("MasterDNS answered through {n} resolvers."),
                        };
                        send(Event::Probed(id, text));
                    });
                }
            }
        }
    }

    /// Something a server task reported.
    pub(crate) fn on_server_event(&mut self, event: Event) {
        let failed_install = matches!(event, Event::Installed(Err(_)));
        let effects = self.servers.on_event(event);
        if failed_install {
            self.toasts
                .error("The install stopped. Read why on the page.");
        }
        self.run_server_effects(effects);
    }

    /// Called from the housekeeping tick: ask for fresh figures while a
    /// server page is open.
    pub(crate) fn tick_servers(&mut self) {
        let effects = self.servers.tick(Instant::now());
        if !effects.is_empty() {
            self.run_server_effects(effects);
        }
    }

    /// Write a server's client files (MasterDNS config and key) into a folder
    /// in the home directory, readable by the owner only, and say where.
    fn save_server_files(&mut self, id: &str) {
        let Some(record) = self.servers.record(id).cloned() else {
            return;
        };
        let files: Vec<_> = record
            .client_configs()
            .into_iter()
            .flat_map(|c| c.files)
            .collect();
        if files.is_empty() {
            self.toasts
                .info("This server's configs are links: copy them instead.");
            return;
        }
        let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
        else {
            self.toasts.error("Could not find your home folder.");
            return;
        };
        let name: String = record
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let dir = std::path::PathBuf::from(home).join(format!("zray-server-{name}"));
        match write_private_files(&dir, &files) {
            Ok(()) => self.toasts.success(format!("Saved to {}", dir.display())),
            Err(e) => self.toasts.error(format!("Could not save the files: {e}")),
        }
    }
}

/// Make `dir` (owner only) and write each file in it, owner-readable only: the
/// files hold the tunnel's key.
fn write_private_files(
    dir: &std::path::Path,
    files: &[zero_provision::record::File],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for file in files {
        // The names come from this program, but only ever use the last part.
        let Some(name) = std::path::Path::new(&file.name).file_name() else {
            continue;
        };
        let path = dir.join(name);
        write_owner_only(&path, file.text.as_bytes())?;
    }
    Ok(())
}

/// Create `path` readable by the owner only from the first byte (no moment
/// where it is world-readable), then fill it.
fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}
