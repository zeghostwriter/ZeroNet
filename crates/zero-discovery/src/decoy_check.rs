//! A check the user can run to see whether hiding the server name works: on
//! this device, and against the network it is on right now.
//!
//! There are two ways of hiding a name, an urgent byte in the middle of it
//! (`zero_evasion::urgent`) and a decoy ClientHello ahead of it
//! (`zero_evasion::decoy`). Whether either works depends on things nobody
//! can see from a settings screen: what the system allows, and what the
//! network's filter does. This module answers with what actually happened,
//! for each way, in three steps, each only run when the one before passed:
//!
//! 1. Does the system offer the way at all?
//! 2. Over the loopback, does a hello sent that way arrive as the real
//!    hello? That is the mechanism itself, with no network involved.
//! 3. Towards a name this network filters: is it cut off as it is, and does
//!    the same hello get an answer with the name hidden?
//!
//! Step 3 opens a few connections to two well-known sites and sends them
//! nothing but a ClientHello. Nothing about the user is in it, and the
//! sockets are protected, so with the tunnel up the check still measures the
//! network itself and not the tunnel.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The name the decoy carries; any name the filter lets through will do.
const DECOY_NAME: &str = "www.microsoft.com";
/// Sites whose names are filtered in Iran, each with an address that serves
/// it. Two different networks (Fastly, Cloudflare), so one being unreachable
/// does not end the check.
const FILTERED: [(Ipv4Addr, &str); 2] = [
    (Ipv4Addr::new(151, 101, 64, 81), "www.bbc.com"),
    (Ipv4Addr::new(104, 16, 132, 229), "www.youtube.com"),
];
const CONNECT_WITHIN: Duration = Duration::from_secs(4);
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// What one hello got back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// The server sent something: the hello reached it.
    Answered,
    /// The connection opened and then nothing came back, or it was reset.
    CutOff,
    /// No TCP connection at all; says nothing about names.
    Unreachable,
}

/// One of the two ways of hiding a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    Urgent,
    Decoy,
}

impl Way {
    fn supported(self) -> bool {
        match self {
            Self::Urgent => zero_evasion::urgent::supported(),
            Self::Decoy => zero_evasion::decoy::supported(),
        }
    }
}

/// Run the check. The answer is `{"supported", "local", "network", "urgent",
/// "decoy"}`. `urgent` and `decoy` each hold that way's own `supported`,
/// `local` (steps 1 and 2) and `network`, which is one of
///
/// * `"works"`: a name was cut off as it is and answered with it hidden;
/// * `"not_needed"`: nothing was cut off, so there was nothing to get past;
/// * `"blocked"`: a name was cut off and stayed cut off with it hidden;
/// * `"offline"`: no test site could be reached at all;
/// * `"skipped"`: step 1 or 2 failed, so the network was not asked.
///
/// The three fields at the top say the same for the device as a whole: the
/// better of the two ways, which is what the apps show.
pub async fn decoy_check() -> Value {
    // What the network does to a filtered name as it is, asked once.
    let mut plain = Vec::with_capacity(FILTERED.len());
    for (ip, name) in FILTERED {
        plain.push(send(SocketAddr::from((ip, 443)), name, None).await);
    }
    let mut ways = Vec::with_capacity(2);
    for way in [Way::Urgent, Way::Decoy] {
        let supported = way.supported();
        let local = supported && local_round_trip(way).await;
        let network = if local {
            network(way, &plain).await
        } else {
            "skipped"
        };
        ways.push((supported, local, network));
    }
    // Best first: a way that got a name through, then one that at least
    // works on the device.
    let rank = |network: &str| match network {
        "works" => 0,
        "not_needed" => 1,
        "offline" => 2,
        "blocked" => 3,
        _ => 4,
    };
    let best = ways
        .iter()
        .map(|(_, _, network)| *network)
        .min_by_key(|network| rank(network))
        .unwrap_or("skipped");
    let one = |(supported, local, network): (bool, bool, &str)| json!({"supported": supported, "local": local, "network": network});
    json!({
        "supported": ways.iter().any(|way| way.0),
        "local": ways.iter().any(|way| way.1),
        "network": best,
        "urgent": one(ways[0]),
        "decoy": one(ways[1]),
    })
}

/// The user's switch for hiding server names, for the apps: off stops every
/// automatic use of either way from the next connection on
/// (`zero_evasion::decoy::set_enabled`).
pub fn set_decoy_enabled(enabled: bool) {
    zero_evasion::decoy::set_enabled(enabled);
}

/// A ClientHello naming `name`, the same every caller of this module sends.
fn hello(name: &str) -> Option<Vec<u8>> {
    zero_evasion::build_fake_client_hello(name).ok()
}

/// Step 2: a hello sent `way` to a listener of our own. True when what
/// arrives is the real hello, byte for byte.
///
/// The listener reads with blocking calls on a thread of its own, as most
/// servers do: a read stops at an urgent mark, and only a reader that asks
/// the kernel again carries on past it (`zero_evasion::urgent`).
async fn local_round_trip(way: Way) -> bool {
    let attempt = async {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let client = tokio::net::TcpStream::connect(listener.local_addr().ok()?)
            .await
            .ok()?;
        let real = hello("filtered.example.com")?;
        let wanted = real.len();
        let reading = tokio::task::spawn_blocking(move || {
            zero_evasion::urgent::read_past_the_mark(&listener, wanted)
        });
        match way {
            Way::Urgent => zero_evasion::UrgentStream::new(client)
                .write_all(&real)
                .await
                .ok()?,
            Way::Decoy => zero_evasion::DecoyStream::new(client, DECOY_NAME)
                .write_all(&real)
                .await
                .ok()?,
        }
        Some(reading.await.ok()? == real)
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(8), attempt).await,
        Ok(Some(true))
    )
}

/// Step 3 for one way, over every site in [`FILTERED`] until one settles
/// it. `plain` is what each site answered to the hello as it is.
async fn network(way: Way, plain: &[Fate]) -> &'static str {
    let mut reached = false;
    let mut blocked = false;
    for ((ip, name), plain) in FILTERED.into_iter().zip(plain) {
        match plain {
            Fate::Unreachable => continue,
            Fate::Answered => reached = true,
            Fate::CutOff => {
                reached = true;
                if send(SocketAddr::from((ip, 443)), name, Some(way)).await == Fate::Answered {
                    return "works";
                }
                blocked = true;
            }
        }
    }
    match (reached, blocked) {
        (false, _) => "offline",
        (true, true) => "blocked",
        (true, false) => "not_needed",
    }
}

/// One hello naming `name` to `address`, as it is or with the name hidden.
async fn send(address: SocketAddr, name: &str, hidden: Option<Way>) -> Fate {
    let Some(hello) = hello(name) else {
        return Fate::Unreachable;
    };
    let connecting = zero_core::platform::connect_protected(address);
    let Ok(Ok(tcp)) = tokio::time::timeout(CONNECT_WITHIN, connecting).await else {
        return Fate::Unreachable;
    };
    let exchange = async {
        let mut first = [0u8; 1];
        match hidden {
            Some(Way::Decoy) => {
                let mut stream = zero_evasion::DecoyStream::new(tcp, DECOY_NAME);
                stream.write_all(&hello).await.ok()?;
                stream.read_exact(&mut first).await.ok()
            }
            Some(Way::Urgent) => {
                let mut stream = zero_evasion::UrgentStream::new(tcp);
                stream.write_all(&hello).await.ok()?;
                stream.read_exact(&mut first).await.ok()
            }
            None => {
                let mut stream = tcp;
                stream.write_all(&hello).await.ok()?;
                stream.read_exact(&mut first).await.ok()
            }
        }
    };
    match tokio::time::timeout(ANSWER_WITHIN, exchange).await {
        Ok(Some(_)) => Fate::Answered,
        _ => Fate::CutOff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The part that needs no network: each way the system offers delivers
    /// the hello as written, and the test hello is one a name can be read
    /// out of (or step 2 would pass without hiding anything).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_local_step_delivers_the_real_hello_each_way() {
        for way in [Way::Urgent, Way::Decoy] {
            if !way.supported() {
                eprintln!("skipped {way:?}: this system does not offer it");
                continue;
            }
            assert!(local_round_trip(way).await, "{way:?}");
        }
    }
}
