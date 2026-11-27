//! What the app remembers about a server it set up.
//!
//! The record lives on the user's own device and is the only place the app
//! keeps anything about the server. It holds what is needed to come back and to
//! rebuild the client links: the address, how to log in (the app's own SSH key
//! once it is installed), the pinned host key, and the public facts of each
//! service. The server's private keys (REALITY's) are *not* here: they exist
//! only in the server's config file.
//!
//! `ssh_key` is a secret that opens the server; apps store the record in
//! private storage only and show a "remove access" action that deletes the key
//! on both ends.

use serde::{Deserialize, Serialize};

use crate::links;
use crate::ssh::HostKey;

/// The record's format version, for the day it changes.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reality {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    pub users: Vec<User>,
}

/// VLESS over XHTTP, wrapped in REALITY like [`Reality`] and sharing its keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xhttp {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    /// The request path the server answers on; a client must use the same one.
    pub path: String,
    pub users: Vec<User>,
}

/// ZeroV1 wrapped in REALITY like [`Reality`], sharing its keys and its user
/// list: a user's ZeroV1 id is their VLESS UUID's sixteen bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zerov1 {
    pub tag: String,
    pub port: u16,
    pub sni: String,
    /// REALITY's public key (the private half stays in the server's config).
    pub public_key: String,
    pub short_id: String,
    /// ZeroV1's own public key, which every link carries.
    pub server_key: String,
    /// The path the server answers ZeroV1 requests on.
    pub path: String,
    pub users: Vec<User>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterDns {
    /// The tunnel domain, delegated to the server.
    pub domain: String,
    /// The name server host that domain points to (`ns.example.com`).
    pub ns_host: String,
    /// The program's encryption method id (5 = AES-256-GCM).
    pub method: u8,
    /// The shared key. A client secret: it goes into the client's config.
    pub key: String,
    /// The release of the upstream server that was installed.
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Service {
    Reality(Reality),
    Xhttp(Xhttp),
    Zerov1(Zerov1),
    MasterDns(MasterDns),
}

impl Service {
    /// The inbound tag the usage figures are reported under.
    pub fn tag(&self) -> &str {
        match self {
            Service::Reality(r) => &r.tag,
            Service::Xhttp(x) => &x.tag,
            Service::Zerov1(z) => &z.tag,
            Service::MasterDns(_) => "masterdns",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Service::Reality(_) => "VLESS + REALITY",
            Service::Xhttp(_) => "VLESS + XHTTP + REALITY",
            Service::Zerov1(_) => "ZeroV1 + REALITY",
            Service::MasterDns(_) => "MasterDnsVPN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRecord {
    pub version: u32,
    pub id: String,
    pub name: String,
    /// The address the person typed: an IP or a domain.
    pub host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub host_key: HostKey,
    /// The app's own key, once installed on the server. Secret.
    pub ssh_key: Option<String>,
    pub os: String,
    pub zray_version: String,
    /// Loopback port of the management API on the server.
    pub management_port: u16,
    /// Whether the downloaded program was checked against the signed list.
    pub verified_download: bool,
    pub services: Vec<Service>,
    pub created: u64,
}

/// A file a client program reads, ready to save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct File {
    pub name: String,
    pub text: String,
}

/// One config a person can hand to a client: a link an app imports, and for
/// MasterDNS also the files the upstream client program reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientConfig {
    pub service: &'static str,
    /// Who it is for (`Main`, `Ali`, ...).
    pub user: String,
    pub link: Option<String>,
    pub files: Vec<File>,
}

impl ServerRecord {
    /// Every client config of every service, ready to show, copy or scan.
    pub fn client_configs(&self) -> Vec<ClientConfig> {
        let mut out = Vec::new();
        for service in &self.services {
            match service {
                Service::Reality(r) => {
                    for user in &r.users {
                        out.push(ClientConfig {
                            service: "reality",
                            user: user.name.clone(),
                            link: Some(links::vless_reality(
                                &self.host,
                                r.port,
                                &user.id,
                                &r.sni,
                                &r.public_key,
                                &r.short_id,
                                &format!("{} · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::Xhttp(x) => {
                    for user in &x.users {
                        out.push(ClientConfig {
                            service: "xhttp",
                            user: user.name.clone(),
                            link: Some(links::vless_xhttp_reality(
                                &self.host,
                                x.port,
                                &user.id,
                                &x.sni,
                                &x.public_key,
                                &x.short_id,
                                &x.path,
                                &format!("{} · XHTTP · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::Zerov1(z) => {
                    for user in &z.users {
                        out.push(ClientConfig {
                            service: "zerov1",
                            user: user.name.clone(),
                            link: Some(links::zerov1_reality(
                                &self.host,
                                z.port,
                                &user.id,
                                &z.server_key,
                                &z.path,
                                &z.sni,
                                &z.public_key,
                                &z.short_id,
                                &format!("{} · ZeroV1 · {}", self.name, user.name),
                            )),
                            files: Vec::new(),
                        });
                    }
                }
                Service::MasterDns(m) => out.push(ClientConfig {
                    service: "masterdns",
                    user: "Main".to_string(),
                    link: Some(links::masterdns(
                        &self.host,
                        m,
                        &format!("{} · MasterDNS", self.name),
                    )),
                    files: links::masterdns_client_files(m),
                }),
            }
        }
        out
    }
}
