//! `zeronet-warp` — get a Cloudflare WARP account, and look for edge
//! addresses that work on this network.
//!
//! ```text
//! zeronet-warp register --accept-tos [--route auto|wireguard|masque-h2|masque-h3]
//!                       [--proxy 127.0.0.1:10809]
//!                       [--relay https://worker/path/warp --auth CREDENTIAL]
//! zeronet-warp scan <warp:// link | ->
//! zeronet-warp gather <warp:// link | -> [--want 5] [--sample 150] [--warp-first] [--exit-first]
//! ```
//!
//! `register` makes the keys on this machine, sends only their public halves
//! to Cloudflare, and prints a `warp://` link that any front end imports.
//! It creates an account with Cloudflare, so it does nothing without
//! `--accept-tos`, which says the person running it has read
//! <https://www.cloudflare.com/application/terms/>.
//!
//! Where Cloudflare's API is filtered by name, reach it through a running
//! tunnel (`--proxy` names its HTTP listener) or a relay.
//!
//! `scan` tries edge addresses next to the ones in the link over HTTP/2 and
//! prints the ones that accept the account, fastest first.
//!
//! `gather` reads the public feeds and finds servers worth keeping, then
//! prints a new `warp://` link listing them.
//!
//! The link it writes names the order `hybrid` means by default: a listed
//! server is dialled first and Cloudflare's tunnel is brought up *through* it,
//! so the local network sees an ordinary server and never sees Cloudflare.
//! `--warp-first` asks for the other order — the tunnel is dialled directly and
//! a listed server is reached from inside it — which is the one that reaches
//! servers Iran blocks outright, since those can still be reached from
//! Cloudflare's network. `--exit-first` then picks which of the two carries
//! traffic once the tunnel is up.

use std::time::Duration;

use zero_discovery::warp::{register, Api};

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  zeronet-warp register --accept-tos [--route auto] [--proxy ADDR] [--relay URL --auth CREDENTIAL]\n  zeronet-warp scan <warp:// link | ->\n  zeronet-warp gather <warp:// link | -> [--want N] [--sample N] [--warp-first] [--exit-first]"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("register") => run_register(&args[1..]).await,
        Some("scan") => run_scan(&args[1..]).await,
        Some("gather") => run_gather(&args[1..]).await,
        _ => usage(),
    };
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

async fn run_register(args: &[String]) -> Result<(), String> {
    if !args.iter().any(|argument| argument == "--accept-tos") {
        return Err(
            "This creates a Cloudflare WARP account. Read https://www.cloudflare.com/application/terms/ and run again with --accept-tos."
                .into(),
        );
    }
    let route = value(args, "--route").unwrap_or("auto");
    if zero_config::WarpRoute::parse(route).is_none() {
        return Err(format!(
            "--route must be auto, wireguard, masque-h2 or masque-h3, not {route:?}"
        ));
    }
    let mut api = match (value(args, "--relay"), value(args, "--auth")) {
        (Some(base), Some(credential)) => Api::relay(base, credential),
        (Some(_), None) => return Err("--relay needs --auth".into()),
        _ => Api::direct(),
    };
    if let Some(proxy) = value(args, "--proxy") {
        api.proxy = Some(proxy.parse().map_err(|_| {
            format!("--proxy must be an address like 127.0.0.1:10809, not {proxy:?}")
        })?);
    }
    let mut last = String::new();
    // The service limits new accounts now and then; a pause usually clears it.
    for attempt in 0..3 {
        if attempt > 0 {
            eprintln!("Trying again in a minute…");
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        match register(&api).await {
            Ok(account) => {
                println!("{}", account.link(route));
                if account.masque.is_none() {
                    eprintln!("Note: the account has no MASQUE key; it will use WireGuard only.");
                }
                return Ok(());
            }
            Err(error) if error.contains("try again") => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

/// The link named by the first argument, or read from stdin for `-`. A link
/// holds the account's keys; on stdin it stays out of the process list.
fn read_link(args: &[String]) -> Result<String, String> {
    let link = args
        .first()
        .ok_or("this needs a warp:// link (or - to read it from stdin)")?;
    if link == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .map_err(|error| format!("reading stdin: {error}"))?;
        Ok(text.trim().to_string())
    } else {
        Ok(link.clone())
    }
}

async fn run_scan(args: &[String]) -> Result<(), String> {
    let link = read_link(args)?;
    let parsed = zero_config::parse_link(&link)?;
    let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol else {
        return Err("that is not a warp:// link".into());
    };
    let masque = warp
        .masque
        .as_deref()
        .ok_or("that account has no MASQUE key to scan with")?;
    eprintln!("Trying 64 addresses next to the configured ones…");
    let found = zero_runtime::warp::scan_endpoints(masque, 64, 64, Duration::from_secs(40)).await;
    if found.is_empty() {
        return Err("No other address answered from this network.".into());
    }
    for (address, took) in &found {
        println!("{address} {} ms", took.as_millis());
    }
    Ok(())
}

async fn run_gather(args: &[String]) -> Result<(), String> {
    let link = read_link(args)?;
    let want: usize = value(args, "--want")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let sample: usize = value(args, "--sample")
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    // `--server-first` is the default order; `--warp-first` keeps the tunnel as
    // the outer connection, and `--exit-first` picks which of the two carries
    // traffic once the tunnel is up.
    let warp_first = args.iter().any(|argument| argument == "--warp-first");
    let exit_first = args.iter().any(|argument| argument == "--exit-first");
    let hybrid = if warp_first {
        zero_config::HybridMode::WarpFirst
    } else {
        zero_config::HybridMode::ServerFirst
    };
    let exits = zero_discovery::warp::gather_exits(
        &link,
        hybrid,
        want,
        sample,
        Duration::from_secs(120),
        |line| eprintln!("{line}"),
    )
    .await?;
    if exits.is_empty() {
        return Err("No server carried a request.".into());
    }
    println!(
        "{}",
        zero_discovery::warp::link_with_exits(&link, &exits, hybrid, exit_first)?
    );
    Ok(())
}
