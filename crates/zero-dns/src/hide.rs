//! Reaching an encrypted resolver through a filter that reads server names.
//!
//! Before the tunnel is up, the engine asks DoH/DoT resolvers (by address:
//! `1.1.1.1`, `8.8.8.8`, `9.9.9.9`) for the address of a server's domain. On a
//! network that resets or drops a ClientHello it dislikes, those handshakes
//! die and the domain never resolves.
//!
//! The way out is the one the proxy dials use: TCP Fast Open puts the hello in
//! the SYN, where a filter that reads the stream after the handshake does not
//! look ([`zero_net::fastopen`]). It is not the default: a plain handshake
//! costs one round trip less than the first Fast Open dial (which fetches the
//! cookie). So the order is
//!
//! 1. plain, unless this address is remembered as needing the other way;
//! 2. when a plain handshake fails, once more with Fast Open at once, and if
//!    that works the address is remembered for [`HIDE_FOR`];
//! 3. a remembered address that fails with Fast Open is forgotten, so a
//!    network that changed is not stuck on the slower way.
//!
//! The thing that would surprise a newcomer: a Fast Open socket is connected
//! "later" (it has no peer until the first write), so a dead address shows up
//! in the handshake, not in the dial. A server that gives no Fast Open leaves
//! an ordinary connection and is marked, so it is not asked again for an hour.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zero_net::{dial_tcp, fastopen, RacePolicy, SocketOptions};

use crate::{io_error, ResolveError, DNS_TIMEOUT};

/// How long an address stays on Fast Open after a plain handshake failed and
/// Fast Open worked.
const HIDE_FOR: Duration = Duration::from_secs(30 * 60);
/// How long an address that gave no Fast Open is left on plain.
const NO_FAST_FOR: Duration = Duration::from_secs(60 * 60);
/// How long a plain handshake gets when a Fast Open retry is waiting behind
/// it: a filter that cuts the hello leaves it silent, and the full budget
/// would be spent before the retry even starts.
const PLAIN_FIRST: Duration = Duration::from_secs(3);
/// Most addresses remembered; resolvers are few, this only bounds a hostile
/// configuration.
const MAX_REMEMBERED: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Memory {
    /// A plain handshake failed here and Fast Open worked.
    NeedsFastOpen,
    /// The server answers no Fast Open.
    NoFastOpen,
}

static REMEMBERED: Mutex<Option<HashMap<SocketAddr, (Memory, Instant)>>> = Mutex::new(None);

fn with_memory<T>(f: impl FnOnce(&mut HashMap<SocketAddr, (Memory, Instant)>) -> T) -> T {
    let mut guard = REMEMBERED.lock().unwrap_or_else(|e| e.into_inner());
    let table = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    table.retain(|_, (_, until)| *until > now);
    f(table)
}

fn recall(server: SocketAddr) -> Option<Memory> {
    with_memory(|table| table.get(&server).map(|(memory, _)| *memory))
}

fn remember(server: SocketAddr, memory: Memory) {
    let lasts = match memory {
        Memory::NeedsFastOpen => HIDE_FOR,
        Memory::NoFastOpen => NO_FAST_FOR,
    };
    with_memory(|table| {
        if table.len() < MAX_REMEMBERED || table.contains_key(&server) {
            table.insert(server, (memory, Instant::now() + lasts));
        }
    });
}

fn forget(server: SocketAddr) {
    with_memory(|table| table.remove(&server));
}

/// One TCP connection to `target` that puts the first write in the SYN.
/// Marks the address when the server gave no Fast Open (the connection is
/// then an ordinary one, still usable).
async fn dial_fast(target: SocketAddr) -> Result<TcpStream, ResolveError> {
    let policy = RacePolicy {
        connect_timeout: DNS_TIMEOUT,
        ..RacePolicy::default()
    };
    let options = SocketOptions {
        fast_open_if: Some(|_| true),
        ..SocketOptions::default()
    };
    let dialed = dial_tcp(&[target], &policy, &options)
        .await
        .map_err(|failure| ResolveError::Transport(failure.to_string()))?;
    if !fastopen::deferred(&dialed.stream) {
        remember(target, Memory::NoFastOpen);
    }
    Ok(dialed.stream)
}

/// A TLS connection to a resolver at `target`, the way described in the
/// module comment. `name` and `connector` are the caller's; `label` only
/// words the error ("DoT", "DoH").
pub(crate) async fn tls_connect(
    target: SocketAddr,
    connector: &TlsConnector,
    name: &rustls_pki_types::ServerName<'static>,
    label: &str,
) -> Result<TlsStream<TcpStream>, ResolveError> {
    let usable =
        target.is_ipv4() && fastopen::supported() && recall(target) != Some(Memory::NoFastOpen);
    let mut fast = usable && recall(target) == Some(Memory::NeedsFastOpen);
    let mut failed_plain = false;
    loop {
        let budget = if usable && !fast {
            PLAIN_FIRST
        } else {
            DNS_TIMEOUT
        };
        match attempt(target, fast, budget, connector, name, label).await {
            Ok(stream) => {
                // A server that gave no Fast Open was marked while dialling;
                // its plain retry working says nothing about Fast Open.
                if failed_plain && recall(target) != Some(Memory::NoFastOpen) {
                    remember(target, Memory::NeedsFastOpen);
                }
                return Ok(stream);
            }
            Err(error) if usable && !fast => {
                failed_plain = true;
                fast = true;
                tracing::debug!(%target, %error, "resolver handshake failed, trying Fast Open");
            }
            Err(error) => {
                if fast && !failed_plain {
                    forget(target);
                }
                return Err(error);
            }
        }
    }
}

async fn attempt(
    target: SocketAddr,
    fast: bool,
    budget: Duration,
    connector: &TlsConnector,
    name: &rustls_pki_types::ServerName<'static>,
    label: &str,
) -> Result<TlsStream<TcpStream>, ResolveError> {
    let tcp = if fast {
        dial_fast(target).await?
    } else {
        timeout(DNS_TIMEOUT, zero_core::platform::connect_protected(target))
            .await
            .map_err(|_| ResolveError::Transport(format!("{label} connect timed out")))?
            .map_err(io_error)?
    };
    let _ = tcp.set_nodelay(true);
    timeout(budget, connector.connect(name.clone(), tcp))
        .await
        .map_err(|_| ResolveError::Transport(format!("{label} handshake timed out")))?
        .map_err(|e| ResolveError::Transport(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, because the memory is process-wide: two tests filling it
    /// at once would crowd each other out.
    #[test]
    fn the_memory_recalls_forgets_and_stays_bounded() {
        let server: SocketAddr = "203.0.113.7:853".parse().unwrap();
        assert_eq!(recall(server), None);
        remember(server, Memory::NeedsFastOpen);
        assert_eq!(recall(server), Some(Memory::NeedsFastOpen));
        forget(server);
        assert_eq!(recall(server), None);
        for i in 0..(MAX_REMEMBERED + 20) {
            let other: SocketAddr = format!("198.51.100.{}:{}", i % 250, 1000 + i)
                .parse()
                .unwrap();
            remember(other, Memory::NoFastOpen);
        }
        assert!(with_memory(|table| table.len()) <= MAX_REMEMBERED);
    }
}
