//! The installer as one string-in, events-out job, for apps that cannot call
//! Rust types directly (Android reaches it through JNI, see `zray-mobile`).
//!
//! A request is one JSON object with an `op`; the job emits JSON events to the
//! sink and always ends with exactly one `{"t":"done","ok":…}`:
//!
//! | `op`          | needs                                             | `done` carries                      |
//! |---------------|---------------------------------------------------|-------------------------------------|
//! | `fingerprint` | `host`, `port`                                    | `fingerprint`, `algorithm`          |
//! | `dns_plan`    | `domain`, `server`                                | `domain`, `ns_host`, `records`      |
//! | `dns`         | `ns_host`, `server`                               | `status`: right, wrong or unknown   |
//! | `install`     | login, `trust`, `name`, what to install           | `record`, `notes`, `configs`        |
//! | `usage`       | `record`                                          | `usage`                             |
//! | `remove`      | `record`                                          | nothing                             |
//! | `probe`       | `record` (with a MasterDNS service)               | `answered`, `of`, `best_ms`         |
//! | `configs`     | `record`                                          | `configs`                           |
//!
//! `install` and `remove` also emit `{"t":"step",…}` and `{"t":"detail",…}`
//! as they go. Failures are `{"t":"done","ok":false,"error":"<a sentence for
//! the person>"}`; the app shows it as it is.
//!
//! The record is passed in and out as JSON and kept by the app: this job
//! stores nothing. The password in an `install` request is used for that run
//! and dropped with the request.

use serde::Deserialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use zero_discovery::discover::EndReason;
use zero_discovery::events::EventSink;

use crate::install::{
    self, BinarySource, MasterDnsRequest, RealityRequest, XhttpRequest, Zerov1Request,
};
use crate::record::{ServerRecord, Service};
use crate::ssh::{Auth, HostKey, Login};
use crate::{manage, probe, ssh};

/// What the app asks for.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Fingerprint { host: String, port: u16 },
    DnsPlan { domain: String, server: String },
    Dns { ns_host: String, server: String },
    Install(Box<InstallArgs>),
    Usage { record: Box<ServerRecord> },
    Remove { record: Box<ServerRecord> },
    Probe { record: Box<ServerRecord> },
    Configs { record: Box<ServerRecord> },
}

#[derive(Deserialize)]
pub struct InstallArgs {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The login password; empty when a key is used instead.
    #[serde(default)]
    pub password: String,
    /// An SSH private key to log in with instead of a password (text, as
    /// pasted or read from a file) and its passphrase when it has one. Both
    /// are used for this request only and never stored.
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    /// The fingerprint the person confirmed.
    pub trust: HostKey,
    pub name: String,
    #[serde(default)]
    pub reality: bool,
    /// Also (or only) install VLESS over XHTTP inside REALITY.
    #[serde(default)]
    pub xhttp: bool,
    /// Also (or only) install ZeroV1 inside REALITY.
    #[serde(default)]
    pub zerov1: bool,
    /// The website a REALITY server pretends to be; a default when absent.
    pub sni: Option<String>,
    /// Set to install MasterDNS for this tunnel domain.
    pub masterdns_domain: Option<String>,
    /// A server program on this device to install instead of the signed
    /// release (unverified; reported as such).
    pub local_binary_path: Option<String>,
}

impl std::fmt::Debug for InstallArgs {
    // The password and key never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallArgs")
            .field("host", &self.host)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

const DEFAULT_SNI: &str = "www.microsoft.com";

fn done_err(sink: &EventSink, error: impl std::fmt::Display) -> EndReason {
    sink.emit(json!({"t": "done", "ok": false, "error": error.to_string()}));
    EndReason::Exhausted
}

fn done_ok(sink: &EventSink, mut fields: Value) -> EndReason {
    fields["t"] = json!("done");
    fields["ok"] = json!(true);
    sink.emit(fields);
    EndReason::Enough
}

/// Run one request. Cancelling ends it early with `ok: false`.
pub async fn run(request: Request, sink: EventSink, cancel: CancellationToken) -> EndReason {
    tokio::select! {
        reason = work(request, &sink) => reason,
        () = cancel.cancelled() => {
            sink.emit(json!({"t": "done", "ok": false, "error": "cancelled"}));
            EndReason::Cancelled
        }
    }
}

async fn work(request: Request, sink: &EventSink) -> EndReason {
    match request {
        Request::Fingerprint { host, port } => match ssh::fetch_host_key(&host, port).await {
            Ok(key) => done_ok(
                sink,
                json!({"fingerprint": key.fingerprint, "algorithm": key.algorithm}),
            ),
            Err(e) => done_err(sink, e),
        },
        Request::DnsPlan { domain, server } => {
            let domain = match crate::guide::clean_domain(&domain) {
                Ok(domain) => domain,
                Err(e) => return done_err(sink, e),
            };
            // A server given by name has no address to put in the record yet;
            // the app shows the shape and says to use the server's IP.
            let ip = server
                .parse::<std::net::IpAddr>()
                .unwrap_or_else(|_| std::net::IpAddr::from([0, 0, 0, 0]));
            done_ok(
                sink,
                json!({
                    "ns_host": crate::guide::ns_host(&domain),
                    "records": crate::guide::delegation_records(&domain, ip),
                    "needs_ip": server.parse::<std::net::IpAddr>().is_err(),
                    "domain": domain,
                }),
            )
        }
        Request::Dns { ns_host, server } => {
            let status = match server.parse::<std::net::IpAddr>() {
                Err(_) => "unknown",
                Ok(ip) => {
                    match probe::ns_host_points_here(&ns_host, ip, &probe::public_resolvers()).await
                    {
                        Some(true) => "right",
                        Some(false) => "wrong",
                        None => "unknown",
                    }
                }
            };
            done_ok(sink, json!({"status": status}))
        }
        Request::Install(args) => install_job(*args, sink).await,
        Request::Usage { record } => {
            let conn = match manage::connect(&record).await {
                Ok(conn) => conn,
                Err(e) => return done_err(sink, e),
            };
            let usage = manage::usage(&conn, &record).await;
            conn.close().await;
            match usage {
                Ok(usage) => done_ok(sink, json!({"usage": usage})),
                Err(e) => done_err(sink, e),
            }
        }
        Request::Remove { record } => {
            let conn = match manage::connect(&record).await {
                Ok(conn) => conn,
                Err(e) => return done_err(sink, e),
            };
            let removed = manage::remove(&conn, &record, &|step| {
                sink.emit(json!({"t": "removed", "step": format!("{step:?}").to_lowercase()}));
            })
            .await;
            conn.close().await;
            match removed {
                Ok(()) => done_ok(sink, json!({})),
                Err(e) => done_err(sink, e),
            }
        }
        Request::Probe { record } => {
            let Some(service) = record.services.iter().find_map(|s| match s {
                Service::MasterDns(m) => Some(m),
                _ => None,
            }) else {
                return done_err(sink, "This server has no MasterDNS service.");
            };
            let results = probe::probe_masterdns(service, &probe::public_resolvers()).await;
            let answered = results.iter().filter(|r| r.answered).count();
            let best = results.iter().filter_map(|r| r.millis).min();
            done_ok(
                sink,
                json!({"answered": answered, "of": results.len(), "best_ms": best}),
            )
        }
        Request::Configs { record } => done_ok(sink, json!({"configs": record.client_configs()})),
    }
}

async fn install_job(args: InstallArgs, sink: &EventSink) -> EndReason {
    let domain = match &args.masterdns_domain {
        Some(text) => match crate::guide::clean_domain(text) {
            Ok(domain) => Some(domain),
            Err(e) => return done_err(sink, e),
        },
        None => None,
    };
    let binary = match &args.local_binary_path {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => BinarySource::Local(bytes),
            Err(e) => return done_err(sink, format!("Could not read the server program: {e}")),
        },
        None => BinarySource::Release { tag: None },
    };
    let auth = match args
        .private_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
    {
        Some(key) => {
            let passphrase = args.key_passphrase.clone().filter(|p| !p.is_empty());
            // Fail on a bad key now, before any connection is made.
            if let Err(e) = crate::ssh::parse_private_key(key, passphrase.as_deref()) {
                return done_err(sink, e);
            }
            Auth::UserKey {
                pem: key.to_string(),
                passphrase,
            }
        }
        None if args.password.is_empty() => {
            return done_err(sink, "Give a password or an SSH key to log in with.")
        }
        None => Auth::Password(args.password.clone()),
    };
    let login = Login {
        host: args.host.clone(),
        port: args.port,
        user: args.user.clone(),
        auth,
    };
    let request = install::Request {
        name: args.name.trim().to_string(),
        first_user: "Main".into(),
        reality: args.reality.then(|| RealityRequest {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        xhttp: args.xhttp.then(|| XhttpRequest {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        zerov1: args.zerov1.then(|| Zerov1Request {
            sni: args.sni.clone().unwrap_or_else(|| DEFAULT_SNI.into()),
            port: None,
        }),
        masterdns: domain.map(|domain| MasterDnsRequest { domain }),
        binary,
        keep_access: true,
    };
    let result = install::install(&login, &args.trust, &request, &|event| match event {
        install::Event::Step {
            step,
            preset,
            number,
            of,
        } => sink
            .emit(json!({"t": "step", "step": step, "preset": preset, "number": number, "of": of})),
        install::Event::Detail(text) => sink.emit(json!({"t": "detail", "text": text})),
    })
    .await;
    match result {
        Ok(outcome) => done_ok(
            sink,
            json!({
                "configs": outcome.record.client_configs(),
                "record": outcome.record,
                "notes": outcome.notes,
            }),
        ),
        Err(e) => done_err(sink, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Run `request` and return every event it emitted.
    async fn events(request: &str) -> Vec<Value> {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let callback = {
            let seen = Arc::clone(&seen);
            Arc::new(move |batch: String| seen.lock().unwrap().push(batch))
        };
        let (sink, flusher) = zero_discovery::events::batching_sink(callback);
        let request: Request = serde_json::from_str(request).expect("a valid request");
        run(request, sink.clone(), CancellationToken::new()).await;
        drop(sink);
        let _ = flusher.await;
        let all = seen.lock().unwrap().join("\n");
        all.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn the_password_never_prints() {
        let args: InstallArgs = serde_json::from_str(
            r#"{"host":"h","port":22,"user":"root","password":"hunter2","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":true}"#,
        )
        .unwrap();
        assert!(!format!("{args:?}").contains("hunter2"));
    }

    #[test]
    fn unknown_ops_and_missing_fields_are_rejected_at_parse() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"explode"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"fingerprint","host":"h"}"#).is_err());
    }

    #[tokio::test]
    async fn dns_with_a_name_instead_of_an_address_is_unknown() {
        let out = events(r#"{"op":"dns","ns_host":"ns.example.com","server":"not-an-ip"}"#).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["t"], "done");
        assert_eq!(out[0]["status"], "unknown");
    }

    #[tokio::test]
    async fn the_dns_plan_cleans_the_domain_and_lists_two_records() {
        let out =
            events(r#"{"op":"dns_plan","domain":"https://T.Example.com/","server":"203.0.113.7"}"#)
                .await;
        assert_eq!(out[0]["domain"], "t.example.com");
        assert_eq!(out[0]["ns_host"], "ns.example.com");
        let records = out[0]["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["value"], "203.0.113.7");
        assert_eq!(records[1]["kind"], "NS");
        assert_eq!(out[0]["needs_ip"], false);
        let bad =
            events(r#"{"op":"dns_plan","domain":"example.com","server":"203.0.113.7"}"#).await;
        assert_eq!(bad[0]["ok"], false);
        assert!(bad[0]["error"].as_str().unwrap().contains("subdomain"));
    }

    #[tokio::test]
    async fn an_unreachable_server_ends_with_a_sentence() {
        // Port 1 on loopback refuses at once.
        let out = events(r#"{"op":"fingerprint","host":"127.0.0.1","port":1}"#).await;
        let last = out.last().unwrap();
        assert_eq!(
            (last["t"].as_str(), last["ok"].as_bool()),
            (Some("done"), Some(false))
        );
        assert!(
            last["error"]
                .as_str()
                .unwrap()
                .contains("127.0.0.1:1 refused"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn a_bad_domain_stops_the_install_before_any_login() {
        let out = events(
            r#"{"op":"install","host":"127.0.0.1","port":1,"user":"root","password":"p","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":false,"masterdns_domain":"example.com"}"#,
        )
        .await;
        let last = out.last().unwrap();
        assert_eq!(last["ok"], false);
        assert!(
            last["error"].as_str().unwrap().contains("subdomain"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn configs_come_from_the_record() {
        let record = serde_json::json!({
            "version": 1, "id": "a", "name": "n", "host": "203.0.113.7", "ssh_port": 22,
            "ssh_user": "root", "host_key": {"fingerprint": "SHA256:x", "algorithm": "a"},
            "ssh_key": null, "os": "x", "zray_version": "1", "management_port": 1,
            "verified_download": true, "created": 0,
            "services": [{"kind": "reality", "tag": "reality", "port": 443, "sni": "www.microsoft.com",
                "public_key": "pk", "short_id": "ab", "users": [{"name": "Main", "id": "11111111-1111-4111-8111-111111111111"}]}]
        });
        let out = events(&json!({"op": "configs", "record": record}).to_string()).await;
        let configs = out[0]["configs"].as_array().unwrap();
        assert_eq!(configs.len(), 1);
        assert!(configs[0]["link"].as_str().unwrap().starts_with("vless://"));
    }

    #[tokio::test]
    async fn cancelling_ends_with_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let seen = Arc::new(Mutex::new(String::new()));
        let callback = {
            let seen = Arc::clone(&seen);
            Arc::new(move |batch: String| seen.lock().unwrap().push_str(&batch))
        };
        let (sink, flusher) = zero_discovery::events::batching_sink(callback);
        let request = Request::Fingerprint {
            host: "203.0.113.1".into(),
            port: 22,
        };
        let reason = run(request, sink.clone(), cancel).await;
        drop(sink);
        let _ = flusher.await;
        assert_eq!(reason, EndReason::Cancelled);
        assert!(seen.lock().unwrap().contains("cancelled"));
    }

    #[tokio::test]
    async fn an_install_needs_a_password_or_a_usable_key() {
        let install = |extra: &str| {
            format!(
                r#"{{"op":"install","host":"127.0.0.1","port":1,"user":"root",{extra}"trust":{{"fingerprint":"SHA256:x","algorithm":"a"}},"name":"n","reality":true}}"#
            )
        };
        let none = events(&install("")).await;
        assert!(none.last().unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("password or an SSH key"));
        // A public key (or anything that is not a private key) is explained before any connection.
        let public = events(&install(r#""private_key":"ssh-ed25519 AAAA user@host","#)).await;
        let error = public.last().unwrap()["error"].as_str().unwrap();
        assert!(error.contains("not a private key"), "{error}");
        assert!(
            !public.iter().any(|e| e["t"] == "step"),
            "no connection should be tried"
        );
    }

    #[test]
    fn the_key_and_its_passphrase_never_print() {
        let args: InstallArgs = serde_json::from_str(
            r#"{"host":"h","port":22,"user":"root","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----","key_passphrase":"hunter2","trust":{"fingerprint":"SHA256:x","algorithm":"a"},"name":"n","reality":true}"#,
        )
        .unwrap();
        let text = format!("{args:?}");
        assert!(!text.contains("BEGIN") && !text.contains("hunter2"));
    }
}
