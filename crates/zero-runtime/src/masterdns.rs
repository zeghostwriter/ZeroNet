//! The MasterDNS outbound: one tunnel per server, one stream per connection.
//!
//! How it works: the first connection to a server starts a tunnel (the resolver
//! probes and the session handshake, see `zero_masterdns::client`), which takes
//! a few seconds. Every later connection to the same server reuses it and only
//! opens a stream. The tunnel is kept in a process-wide table keyed by the
//! outbound's settings, so two outbounds with the same server share one session
//! and a changed key or resolver list gets its own.
//!
//! Rule it keeps: connects to one server are serialised, so a burst of
//! connections right after start does not run the handshake many times. A failed
//! bring-up is remembered for a few seconds so a burst does not retry it for
//! every connection either; the next connection after that tries again.
//!
//! The thing that surprises newcomers: this outbound is not wrapped in the usual
//! setup deadline, because the first connection legitimately takes as long as
//! the resolver probes do. `zero_masterdns` bounds each step itself.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use zero_config::{MasterDnsConfig, MasterDnsMode};
use zero_core::{boxed, BoxStream, Destination, Failure, FailureKind, Network, Stage};
use zero_masterdns::client::{Client, Config, Error, Mode};

/// How long a failed bring-up is reported as is, without trying again.
const RETRY_AFTER: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Slot {
    client: Option<Arc<Client>>,
    failed: Option<(Instant, Error)>,
}

type Table = Mutex<HashMap<u64, Arc<tokio::sync::Mutex<Slot>>>>;

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(Table::default)
}

fn client_config(cfg: &MasterDnsConfig) -> Config {
    let mut config = Config::new(&cfg.domain, &cfg.key, cfg.resolvers.clone());
    config.method = cfg.method;
    config.mode = match cfg.mode {
        MasterDnsMode::Socks5 => Mode::Socks5,
        MasterDnsMode::Tcp => Mode::Tcp,
    };
    config
}

/// The live tunnel for `cfg`, starting one when there is none (or it died).
async fn tunnel(cfg: &MasterDnsConfig) -> Result<Arc<Client>, Error> {
    let mut hasher = DefaultHasher::new();
    cfg.hash(&mut hasher);
    let slot = table()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(hasher.finish())
        .or_default()
        .clone();
    let mut slot = slot.lock().await;
    if let Some(client) = slot.client.as_ref().filter(|c| c.is_alive()) {
        return Ok(client.clone());
    }
    slot.client = None;
    if let Some((at, error)) = &slot.failed {
        if at.elapsed() < RETRY_AFTER {
            return Err(error.clone());
        }
    }
    match Client::connect(client_config(cfg)).await {
        Ok(client) => {
            let client = Arc::new(client);
            slot.client = Some(client.clone());
            slot.failed = None;
            Ok(client)
        }
        Err(error) => {
            slot.failed = Some((Instant::now(), error.clone()));
            Err(error)
        }
    }
}

fn failure(error: &Error) -> Failure {
    let (kind, stage) = match error {
        Error::NoResolver | Error::NoSession | Error::Io(_) => {
            (FailureKind::TcpUnreachable, Stage::SocketConnected)
        }
        Error::Timeout => (FailureKind::TcpTimeout, Stage::RequestSent),
        Error::Connect(_) => (FailureKind::ProtocolRejected, Stage::RequestSent),
        Error::Config(_) => (FailureKind::LocalPolicy, Stage::Resolving),
        _ => (FailureKind::Unknown, Stage::RequestSent),
    };
    Failure::new(kind, stage).with_detail(error.to_string())
}

/// Open a stream to `destination` through the MasterDNS server `cfg` names.
pub(crate) async fn connect(
    cfg: &MasterDnsConfig,
    destination: &Destination,
) -> Result<BoxStream, Failure> {
    if destination.network != Network::Tcp {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("MasterDNS carries TCP only"));
    }
    let host = match &destination.address {
        zero_core::Address::Ip(ip) => ip.to_string(),
        zero_core::Address::Domain(name) => name.to_string(),
    };
    let client = tunnel(cfg).await.map_err(|e| failure(&e))?;
    let stream = client
        .open(&host, destination.port)
        .await
        .map_err(|e| failure(&e))?;
    Ok(boxed(stream))
}
