//! Installing the servers, over SSH, in steps a person can follow.
//!
//! The rules the installer keeps:
//!
//! * **Look before touching.** The first step only reads; if the server cannot
//!   take the install, it stops there with the reason.
//! * **Nothing unverified runs.** The Zray server program is checked against a
//!   signed hash list before it is placed (see [`crate::release`]); the
//!   MasterDNS server is a pinned release whose hash is in this crate. The one
//!   exception, a program uploaded from the app itself, is reported as
//!   unverified in the result.
//! * **Nothing outside our own names is changed.** Files live under the paths
//!   in [`crate::layout`], each service runs as its own user, and an existing
//!   firewall only ever gets ports added.
//! * **Secrets stay where they belong.** The REALITY private key goes to the
//!   server's config and nowhere else; the password the person typed is used
//!   for this run and dropped; the app's own key is the way back.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use crate::facts::{Facts, Problem};
use crate::guide;
use crate::keys;
use crate::layout::{self, MasterDnsServer, RealityInbound};
use crate::record::{self, MasterDns, Reality, ServerRecord, Service, User, Xhttp, Zerov1};
use crate::release;
use crate::scripts;
use crate::ssh::{self, Auth, Connection, HostKey, Login};

/// What can be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    Reality,
    Xhttp,
    Zerov1,
    MasterDns,
}

/// The long steps of an install; UIs name them in their own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Check,
    Packages,
    Download,
    Install,
    Configure,
    Start,
    Firewall,
    Access,
}

/// Progress for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A step begins. `preset` is set for the steps that belong to one service.
    Step {
        step: Step,
        preset: Option<Preset>,
        number: usize,
        of: usize,
    },
    /// A plain-language detail about the step in progress.
    Detail(String),
}

/// Where the Zray server program comes from.
pub enum BinarySource {
    /// The project's GitHub release, checked against its signed hash list.
    /// `tag` is a release tag, or `None` for the latest.
    Release { tag: Option<String> },
    /// Bytes the app itself holds, installed as they are. Unverified.
    Local(Vec<u8>),
}

pub struct RealityRequest {
    /// The real website the server impersonates to anyone who is not a client.
    pub sni: String,
    /// `None` picks 443, or the first free fallback.
    pub port: Option<u16>,
}

/// VLESS over XHTTP inside REALITY: the same server program and keys as
/// [`RealityRequest`], on its own port.
pub struct XhttpRequest {
    /// The real website the server impersonates (used when REALITY is not
    /// installed too; with both, the REALITY site is shared).
    pub sni: String,
    /// `None` picks 443 when REALITY is not installed, else the first free
    /// fallback.
    pub port: Option<u16>,
}

/// ZeroV1 inside REALITY: the same server program, keys and users as
/// [`RealityRequest`], on its own port.
pub struct Zerov1Request {
    /// The real website the server impersonates (used when neither REALITY
    /// nor XHTTP is installed too; otherwise their site is shared).
    pub sni: String,
    /// `None` picks 443 when it is the only service, else the first free
    /// fallback.
    pub port: Option<u16>,
}

pub struct MasterDnsRequest {
    /// The tunnel domain, as [`guide::clean_domain`] returns it.
    pub domain: String,
}

pub struct Request {
    /// What the person calls this server.
    pub name: String,
    /// Name of the first config (`Main`).
    pub first_user: String,
    pub reality: Option<RealityRequest>,
    pub xhttp: Option<XhttpRequest>,
    pub zerov1: Option<Zerov1Request>,
    pub masterdns: Option<MasterDnsRequest>,
    pub binary: BinarySource,
    /// Install the app's own key so it can come back without the password.
    pub keep_access: bool,
}

/// Something the person should know after the install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Note {
    /// The wanted port was in use, so another was used.
    PortMoved {
        wanted: u16,
        used: u16,
        held_by: String,
    },
    /// A firewall on the server was changed.
    FirewallOpened { which: String },
    /// There was no firewall to change; the hosting provider may have one.
    ProviderFirewall { tcp: Vec<u16>, udp: Vec<u16> },
    /// The program was not checked against the signed list.
    Unverified,
    /// The app could not log back in with its own key.
    KeyNotWorking,
}

pub struct Outcome {
    pub record: ServerRecord,
    pub notes: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Ssh(ssh::Error),
    /// The server cannot take the install.
    Unsupported(Vec<Problem>),
    /// A server program from Zray is already installed here.
    AlreadyInstalled,
    /// Nothing was asked for.
    NothingToInstall,
    /// The domain is not usable.
    Domain(guide::DomainError),
    /// The release is not signed by the key this app trusts.
    BadSignature,
    /// The downloaded program's hash is not the expected one.
    ChecksumMismatch,
    /// The server's system is older than the released program supports.
    SystemTooOld,
    /// A step failed on the server; `detail` is what it said.
    Step {
        step: Step,
        detail: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Ssh(e) => e.fmt(f),
            Error::Unsupported(problems) => {
                let lines: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
                f.write_str(&lines.join(" "))
            }
            Error::AlreadyInstalled => f.write_str(
                "A Zray server is already installed on this machine. Open it from your server \
                 list, or remove it first.",
            ),
            Error::NothingToInstall => f.write_str("Choose at least one thing to install."),
            Error::Domain(e) => e.fmt(f),
            Error::BadSignature => f.write_str(
                "The download could not be verified (its signature does not match the key built \
                 into this app), so nothing was installed. Try again later; if it keeps happening, \
                 update this app.",
            ),
            Error::ChecksumMismatch => f.write_str(
                "The downloaded server program did not match its published checksum, so it was \
                 thrown away and nothing was installed. Try again.",
            ),
            Error::SystemTooOld => f.write_str(
                "This server's system is too old for the server program (it needs a newer C \
                 library). Use Ubuntu 22.04 or newer, or Debian 12 or newer.",
            ),
            Error::Step { step, detail } => write!(f, "The {step:?} step failed: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ssh::Error> for Error {
    fn from(e: ssh::Error) -> Self {
        Error::Ssh(e)
    }
}

const QUICK: Duration = Duration::from_secs(60);
const SLOW: Duration = Duration::from_secs(900);

/// Ports tried, in order, when the wanted one is taken.
const FALLBACK_PORTS: [u16; 5] = [8443, 2053, 2083, 2087, 2096];

/// `chosen` are ports this install already gave to another inbound.
fn pick_port(facts: &Facts, wanted: u16, chosen: &[u16], notes: &mut Vec<Note>) -> u16 {
    let free =
        |p: u16| facts.port_taken_by_other(p, false, false).is_none() && !chosen.contains(&p);
    if free(wanted) {
        return wanted;
    }
    let used = FALLBACK_PORTS
        .iter()
        .copied()
        .find(|p| free(*p))
        .unwrap_or(wanted);
    let held_by = facts.port_taken_by_other(wanted, false, false).map_or_else(
        || "this install's other service".to_string(),
        str::to_string,
    );
    notes.push(Note::PortMoved {
        wanted,
        used,
        held_by,
    });
    used
}

fn management_port(facts: &Facts) -> u16 {
    use rand::Rng;
    loop {
        let port = rand::thread_rng().gen_range(20000..60000);
        if !facts.tcp.iter().any(|l| l.port == port) {
            return port;
        }
    }
}

fn fail(step: Step, out: &ssh::Output) -> Error {
    let detail = out.stderr.trim();
    if detail.contains("GLIBC_") {
        return Error::SystemTooOld;
    }
    Error::Step {
        step,
        detail: if detail.is_empty() {
            format!("exit status {}", out.status)
        } else {
            detail.lines().last().unwrap_or(detail).to_string()
        },
    }
}

/// Counts the steps as they are announced so the screen can show "3 of 9".
struct Progress<'a> {
    on: &'a (dyn Fn(Event) + Sync),
    done: usize,
    of: usize,
}

impl Progress<'_> {
    fn step(&mut self, step: Step, preset: Option<Preset>) {
        self.done += 1;
        (self.on)(Event::Step {
            step,
            preset,
            number: self.done,
            of: self.of,
        });
    }

    fn detail(&self, text: impl Into<String>) {
        (self.on)(Event::Detail(text.into()));
    }
}

fn list(ports: &[u16]) -> String {
    if ports.is_empty() {
        "none".to_string()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Install what `request` asks for. `login` is the first login (a password);
/// `host_key` is what the person confirmed. See the module text for the rules.
pub async fn install(
    login: &Login,
    host_key: &HostKey,
    request: &Request,
    on: &(dyn Fn(Event) + Sync),
) -> Result<Outcome, Error> {
    // REALITY, XHTTP and ZeroV1 share one server program, so they count as one
    // preset.
    let zray = request.reality.is_some() || request.xhttp.is_some() || request.zerov1.is_some();
    let presets = usize::from(zray) + usize::from(request.masterdns.is_some());
    if presets == 0 {
        return Err(Error::NothingToInstall);
    }
    let masterdns_domain = match &request.masterdns {
        Some(m) => Some(guide::clean_domain(&m.domain).map_err(Error::Domain)?),
        None => None,
    };
    let mut progress = Progress {
        on,
        done: 0,
        of: 4 + 4 * presets,
    };
    let mut notes = Vec::new();
    let id = keys::random_hex(8);

    // Look.
    progress.step(Step::Check, None);
    let conn = ssh::connect(login, &host_key.fingerprint).await?;
    let probe = conn.script(&[], crate::facts::SCRIPT, QUICK).await?;
    if !probe.ok() {
        return Err(if probe.stderr.contains("sudo") {
            Error::Unsupported(vec![Problem::NeedRoot])
        } else {
            fail(Step::Check, &probe)
        });
    }
    let facts = Facts::parse(&probe.stdout);
    progress.detail(format!("{} · {} MB memory", facts.os_name, facts.mem_mb));
    let mut problems = facts.problems();
    // MasterDNS needs port 53 for itself, on UDP. A resolver listening only on
    // loopback (systemd-resolved's stub) is fine: the server then binds the
    // machine's own address instead of every address.
    let mut dns_bind = "0.0.0.0".to_string();
    if masterdns_domain.is_some() {
        if let Some(process) = facts.port_taken_by_other(53, true, true) {
            problems.push(Problem::PortInUse {
                port: 53,
                process: process.to_string(),
            });
        } else if facts.udp.iter().any(|l| l.port == 53 && l.loopback_only()) {
            if facts.primary_ip4.is_empty() {
                problems.push(Problem::PortInUse {
                    port: 53,
                    process: "the system resolver".into(),
                });
            } else {
                dns_bind = facts.primary_ip4.clone();
            }
        }
    }
    if !problems.is_empty() {
        return Err(Error::Unsupported(problems));
    }
    if facts.zray_installed && facts.zray_config && zray {
        return Err(Error::AlreadyInstalled);
    }
    if facts.masterdns_installed && request.masterdns.is_some() {
        return Err(Error::AlreadyInstalled);
    }
    let arch = facts.asset_arch().expect("checked by problems()");

    // Tools.
    progress.step(Step::Packages, None);
    let out = conn.script(&[], scripts::TOOLS, SLOW).await?;
    if !out.ok() {
        return Err(Error::Unsupported(vec![Problem::NoDownloader]));
    }

    let mut services = Vec::new();
    let mut tcp_ports = Vec::new();
    let mut udp_ports = Vec::new();
    let mut verified = true;
    let mut version = String::new();
    let mut management = 0;

    if zray {
        let (vision, xhttp, zerov1, deployed) =
            deploy_zray(&conn, &facts, request, arch, &mut progress, &mut notes).await?;
        verified = deployed.verified;
        version = deployed.version;
        management = deployed.management_port;
        if let Some(service) = vision {
            tcp_ports.push(service.port);
            services.push(Service::Reality(service));
        }
        if let Some(service) = xhttp {
            tcp_ports.push(service.port);
            services.push(Service::Xhttp(service));
        }
        if let Some(service) = zerov1 {
            tcp_ports.push(service.port);
            services.push(Service::Zerov1(service));
        }
    }

    if let (Some(domain), Some(_)) = (&masterdns_domain, &request.masterdns) {
        let service = deploy_masterdns(&conn, domain, &dns_bind, arch, &mut progress).await?;
        udp_ports.push(53);
        services.push(Service::MasterDns(service));
    }

    // Firewall.
    progress.step(Step::Firewall, None);
    let (tcp_text, udp_text) = (list(&tcp_ports), list(&udp_ports));
    let env = [("TCP", tcp_text.as_str()), ("UDP", udp_text.as_str())];
    let out = conn.script(&env, scripts::FIREWALL, QUICK).await?;
    match out.stdout.lines().find_map(|l| l.strip_prefix("firewall=")) {
        Some("ufw") => notes.push(Note::FirewallOpened {
            which: "ufw".into(),
        }),
        Some("firewalld") => notes.push(Note::FirewallOpened {
            which: "firewalld".into(),
        }),
        _ => notes.push(Note::ProviderFirewall {
            tcp: tcp_ports.clone(),
            udp: udp_ports.clone(),
        }),
    }

    // The way back.
    progress.step(Step::Access, None);
    let mut ssh_key = None;
    if request.keep_access {
        let key = keys::new_ssh_key(&layout::key_comment(&id));
        conn.put_file(
            &format!("{}/app.pub", layout::WORK_DIR),
            "600",
            "root:root",
            key.public_openssh.as_bytes(),
        )
        .await?;
        let env = [
            ("LOGIN_USER", login.user.as_str()),
            ("WORK", layout::WORK_DIR),
        ];
        let out = conn.script(&env, scripts::ADD_KEY, QUICK).await?;
        if !out.ok() {
            return Err(fail(Step::Access, &out));
        }
        // Prove the key works before the password is forgotten.
        let with_key = Login {
            auth: Auth::Key(key.private_openssh.clone()),
            ..login.clone()
        };
        match ssh::connect(&with_key, &host_key.fingerprint).await {
            Ok(c) => {
                c.close().await;
                ssh_key = Some(key.private_openssh);
            }
            Err(_) => notes.push(Note::KeyNotWorking),
        }
    }
    let _ = conn
        .script(&[("WORK", layout::WORK_DIR)], scripts::CLEAN, QUICK)
        .await;
    conn.close().await;
    if !verified {
        notes.push(Note::Unverified);
    }

    let record = ServerRecord {
        version: record::VERSION,
        id,
        name: request.name.clone(),
        host: login.host.clone(),
        ssh_port: login.port,
        ssh_user: login.user.clone(),
        host_key: host_key.clone(),
        ssh_key,
        os: facts.os_name.clone(),
        zray_version: version,
        management_port: management,
        verified_download: verified,
        services,
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    };
    Ok(Outcome { record, notes })
}

struct Deployed {
    verified: bool,
    version: String,
    management_port: u16,
}

/// Download, install, configure and start the Zray server with the REALITY
/// (Vision), XHTTP and ZeroV1 inbounds the request asks for. They share one
/// REALITY key pair and one user list. Returns the services and facts for the
/// record.
async fn deploy_zray(
    conn: &Connection,
    facts: &Facts,
    request: &Request,
    arch: &str,
    progress: &mut Progress<'_>,
    notes: &mut Vec<Note>,
) -> Result<(Option<Reality>, Option<Xhttp>, Option<Zerov1>, Deployed), Error> {
    let preset = Some(if request.reality.is_some() {
        Preset::Reality
    } else if request.xhttp.is_some() {
        Preset::Xhttp
    } else {
        Preset::Zerov1
    });

    progress.step(Step::Download, preset);
    let mut verified = false;
    let mut version = String::from("local build");
    match &request.binary {
        BinarySource::Release { tag } => {
            let asset = format!("ZrayCore-Linux-{arch}");
            let tag_arg = tag.as_deref().unwrap_or("latest");
            let env = [
                ("REPO", layout::REPO),
                ("TAG", tag_arg),
                ("WORK", layout::WORK_DIR),
            ];
            let out = conn.script(&env, scripts::MANIFEST, QUICK * 2).await?;
            if !out.ok() {
                return Err(fail(Step::Download, &out));
            }
            let field = |name: &str| {
                out.stdout
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{name}=")))
                    .unwrap_or("")
                    .to_string()
            };
            let (found_tag, sums_b64, signature) = (field("tag"), field("sums"), field("sig"));
            let sums = base64::engine::general_purpose::STANDARD
                .decode(sums_b64.as_bytes())
                .map_err(|_| Error::BadSignature)?;
            if !release::sums_are_signed(&sums, &signature) {
                return Err(Error::BadSignature);
            }
            let sums_text = String::from_utf8_lossy(&sums);
            let expected = release::expected_hash(&sums_text, &asset).ok_or(Error::Step {
                step: Step::Download,
                detail: format!("the release has no {asset}"),
            })?;
            progress.detail(format!("{found_tag} · checksum signed"));
            let env = [
                ("REPO", layout::REPO),
                ("TAG", found_tag.as_str()),
                ("ASSET", asset.as_str()),
                ("SHA", expected.as_str()),
                ("WORK", layout::WORK_DIR),
            ];
            let out = conn.script(&env, scripts::FETCH, SLOW).await?;
            match out.status {
                0 => {}
                30 => return Err(Error::ChecksumMismatch),
                _ => return Err(fail(Step::Download, &out)),
            }
            verified = true;
            version = found_tag;
        }
        BinarySource::Local(bytes) => {
            let out = conn
                .script(
                    &[("WORK", layout::WORK_DIR)],
                    "install -d -m 700 \"$WORK\"",
                    QUICK,
                )
                .await?;
            if !out.ok() {
                return Err(fail(Step::Download, &out));
            }
            conn.put_file(
                &format!("{}/program", layout::WORK_DIR),
                "755",
                "root:root",
                bytes,
            )
            .await?;
        }
    }

    progress.step(Step::Install, preset);
    let env = [
        ("SVC_USER", layout::ZRAY_USER),
        ("PROGRAM_DIR", layout::ZRAY_DIR),
        ("ETC_DIR", layout::ZRAY_ETC),
    ];
    let out = conn.script(&env, scripts::USER_AND_DIRS, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }
    let env = [("WORK", layout::WORK_DIR), ("PROGRAM", layout::ZRAY_BIN)];
    let out = conn.script(&env, scripts::PLACE_PROGRAM, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }

    progress.step(Step::Configure, preset);
    let mut chosen = Vec::new();
    let vision_port = request.reality.as_ref().map(|w| {
        let port = pick_port(facts, w.port.unwrap_or(443), &chosen, notes);
        chosen.push(port);
        port
    });
    let xhttp_port = request.xhttp.as_ref().map(|w| {
        let default = if vision_port.is_some() { 8443 } else { 443 };
        pick_port(facts, w.port.unwrap_or(default), &chosen, notes)
    });
    let zerov1_port = request.zerov1.as_ref().map(|w| {
        let default = if chosen.is_empty() && xhttp_port.is_none() {
            443
        } else {
            2083
        };
        let taken: Vec<u16> = chosen.iter().copied().chain(xhttp_port).collect();
        pick_port(facts, w.port.unwrap_or(default), &taken, notes)
    });
    let sni = match (&request.reality, &request.xhttp, &request.zerov1) {
        (Some(w), _, _) => w.sni.clone(),
        (None, Some(w), _) => w.sni.clone(),
        (None, None, Some(w)) => w.sni.clone(),
        (None, None, None) => unreachable!("deploy_zray runs only when one of them is asked for"),
    };
    let path = format!("/{}", keys::random_hex(4));
    // ZeroV1 has its own key pair and path; REALITY's keys are not reused.
    let zerov1_secret = zero_protocol::tide::generate_keypair();
    let zerov1_path = format!("/static/{}", keys::random_hex(6));
    let zerov1_secret_text = zero_protocol::tide::encode_key(&zerov1_secret.0);
    let keys = keys::new_reality_keys();
    let short_id = keys::random_hex(8);
    let users = vec![(request.first_user.clone(), keys::new_uuid())];
    let config = layout::zray_config(
        &RealityInbound {
            sni: &sni,
            private_key: &keys.private,
            short_id: &short_id,
            users: &users,
            vision_port,
            xhttp: xhttp_port.map(|port| (port, path.as_str())),
            zerov1: zerov1_port.map(|port| layout::Zerov1Inbound {
                port,
                path: &zerov1_path,
                secret_key: &zerov1_secret_text,
            }),
        },
        facts.ipv6,
    );
    let body = serde_json::to_vec_pretty(&config).expect("a JSON value always encodes");
    let owner = format!("root:{}", layout::ZRAY_USER);
    conn.put_file(layout::ZRAY_CONFIG, "640", &owner, &body)
        .await?;
    let management = management_port(facts);
    conn.put_file(
        layout::ZRAY_TOKEN,
        "640",
        &owner,
        keys::new_token().as_bytes(),
    )
    .await?;
    conn.put_file(
        layout::ZRAY_UNIT,
        "644",
        "root:root",
        layout::zray_unit(management).as_bytes(),
    )
    .await?;
    // The server checks its own config before it is started, so a mistake
    // shows up here as a message and not as a service that will not stay up.
    let check = format!("{} check {}", layout::ZRAY_BIN, layout::ZRAY_CONFIG);
    let out = conn.exec(&conn.privileged(&check), b"", QUICK).await?;
    if !out.ok() {
        let text = format!("{}{}", out.stdout, out.stderr);
        if text.contains("GLIBC_") {
            return Err(Error::SystemTooOld);
        }
        return Err(Error::Step {
            step: Step::Configure,
            detail: text
                .trim()
                .lines()
                .last()
                .unwrap_or("the config was rejected")
                .to_string(),
        });
    }

    progress.step(Step::Start, preset);
    let env = [("SERVICE", layout::ZRAY_SERVICE)];
    let out = conn.script(&env, scripts::START, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }
    for port in vision_port.iter().chain(&xhttp_port).chain(&zerov1_port) {
        let port_text = port.to_string();
        let env = [("PORT", port_text.as_str()), ("PROTO", "tcp")];
        let out = conn.script(&env, scripts::WAIT_PORT, QUICK).await?;
        if !out.ok() {
            return Err(fail(Step::Start, &out));
        }
    }

    let user_list = || {
        users
            .iter()
            .map(|(name, id)| User {
                name: name.clone(),
                id: id.clone(),
            })
            .collect::<Vec<_>>()
    };
    let vision = vision_port.map(|port| Reality {
        tag: layout::VISION_TAG.into(),
        port,
        sni: sni.clone(),
        public_key: keys.public.clone(),
        short_id: short_id.clone(),
        users: user_list(),
    });
    let xhttp = xhttp_port.map(|port| Xhttp {
        tag: layout::XHTTP_TAG.into(),
        port,
        sni: sni.clone(),
        public_key: keys.public.clone(),
        short_id: short_id.clone(),
        path: path.clone(),
        users: user_list(),
    });
    let zerov1 = zerov1_port.map(|port| Zerov1 {
        tag: layout::ZEROV1_TAG.into(),
        port,
        sni: sni.clone(),
        public_key: keys.public.clone(),
        short_id: short_id.clone(),
        server_key: zero_protocol::tide::encode_key(&zerov1_secret.1),
        path: zerov1_path.clone(),
        users: user_list(),
    });
    Ok((
        vision,
        xhttp,
        zerov1,
        Deployed {
            verified,
            version,
            management_port: management,
        },
    ))
}

/// Download (pinned), install, configure and start the upstream MasterDNS
/// server for `domain`.
async fn deploy_masterdns(
    conn: &Connection,
    domain: &str,
    bind: &str,
    arch: &str,
    progress: &mut Progress<'_>,
) -> Result<MasterDns, Error> {
    let preset = Some(Preset::MasterDns);
    let (asset, sha) = layout::masterdns_asset(arch).expect("checked by problems()");

    progress.step(Step::Download, preset);
    let env = [
        ("REPO", layout::MASTERDNS_REPO),
        ("TAG", layout::MASTERDNS_TAG),
        ("ASSET", asset),
        ("SHA", sha),
        ("WORK", layout::WORK_DIR),
    ];
    let out = conn
        .script(&env, scripts::FETCH_PINNED_ARCHIVE, SLOW)
        .await?;
    match out.status {
        0 => {}
        30 => return Err(Error::ChecksumMismatch),
        _ => return Err(fail(Step::Download, &out)),
    }
    progress.detail(format!(
        "MasterDnsVPN {} · checksum matches",
        layout::MASTERDNS_TAG
    ));

    progress.step(Step::Install, preset);
    let env = [
        ("SVC_USER", layout::MASTERDNS_USER),
        ("PROGRAM_DIR", layout::MASTERDNS_DIR),
        ("ETC_DIR", layout::MASTERDNS_ETC),
    ];
    let out = conn.script(&env, scripts::USER_AND_DIRS, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }
    let env = [
        ("WORK", layout::WORK_DIR),
        ("PROGRAM", layout::MASTERDNS_BIN),
    ];
    let out = conn.script(&env, scripts::PLACE_PROGRAM, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Install, &out));
    }

    progress.step(Step::Configure, preset);
    let key = keys::random_hex(layout::MASTERDNS_KEY_LEN / 2);
    let owner = format!("root:{}", layout::MASTERDNS_USER);
    let config = layout::masterdns_config(&MasterDnsServer {
        domain,
        bind,
        method: 5,
    });
    conn.put_file(layout::MASTERDNS_KEY, "640", &owner, key.as_bytes())
        .await?;
    conn.put_file(layout::MASTERDNS_CONFIG, "640", &owner, config.as_bytes())
        .await?;
    conn.put_file(
        layout::MASTERDNS_UNIT,
        "644",
        "root:root",
        layout::masterdns_unit().as_bytes(),
    )
    .await?;

    progress.step(Step::Start, preset);
    let env = [("SERVICE", layout::MASTERDNS_SERVICE)];
    let out = conn.script(&env, scripts::START, SLOW).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }
    let env = [("PORT", "53"), ("PROTO", "udp")];
    let out = conn.script(&env, scripts::WAIT_PORT, QUICK).await?;
    if !out.ok() {
        return Err(fail(Step::Start, &out));
    }

    Ok(MasterDns {
        domain: domain.to_string(),
        ns_host: guide::ns_host(domain),
        method: 5,
        key,
        release: layout::MASTERDNS_TAG.to_string(),
    })
}
