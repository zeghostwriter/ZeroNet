//! `zray` — command line entry point.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    zero_runtime::tune_allocator();
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "check" | "test" | "-test" => {
            let rest = &args[1..];
            let mut config_path: Option<&str> = None;
            let mut idx = 0;
            while idx < rest.len() {
                let arg = &rest[idx];
                if arg == "-c" || arg == "--config" || arg == "-config" {
                    if idx + 1 < rest.len() {
                        config_path = Some(rest[idx + 1].as_str());
                        idx += 2;
                        continue;
                    }
                } else if let Some(stripped) = arg.strip_prefix("--config=") {
                    config_path = Some(stripped);
                    idx += 1;
                    continue;
                } else if let Some(stripped) = arg.strip_prefix("-config=") {
                    config_path = Some(stripped);
                    idx += 1;
                    continue;
                } else if !arg.starts_with('-') && config_path.is_none() {
                    config_path = Some(arg.as_str());
                }
                idx += 1;
            }
            if let Some(path) = config_path {
                cmd_check(&[path.to_string()])
            } else {
                cmd_check(rest)
            }
        }
        "run" => cmd_run(&args[1..]),
        "-config" | "--config" => {
            // Invocation directly with `-config <file>` without the `run` subcommand (standard V2Ray CLI)
            cmd_run(&args)
        }
        "preset" => cmd_preset(&args[1..]),
        "assets" => cmd_assets(&args[1..]),
        "version" | "-version" | "--version" | "-V" => {
            // v2rayA expects the output to have at least two fields, with fields[0] matching "V2RAY" or "XRAY"
            // e.g. "Xray 26.3.27" or "V2Ray 5.52.0"
            println!("Xray {} (Zray-Core)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => bail!("unknown command {other:?}; try `zray help`"),
    }
}

fn print_usage() {
    println!(
        "zray {}\n\n\
         USAGE:\n  \
         zray check <file>     Parse a config or subscription and report diagnostics\n  \
         zray run <file>       Run the client from a config file\n  \
         zray run <file> -i N  Run config number N from a config array\n  \
         zray run <file> --management ADDR\n  \
                              Expose the authenticated management API\n  \
         zray run <file> --drain-timeout N\n  \
                              Seconds to finish live sessions on shutdown (default 10, 0 = off)\n  \
         zray preset iran <link|file> [options]\n  \
                              Emit an Iran configuration from share links\n  \
         zray assets refresh <file>\n  \
                              Download and validate the config\'s rule sets\n  \
         zray assets check <file>\n  \
                              Report cached rule-set health without fetching\n  \
         zray version\n\n\
         PRESET OPTIONS:\n  \
         --remote-dns NAME     cloudflare (default), google, quad9, adguard\n  \
         --local-dns NAME      google (default), cloudflare, system\n  \
         --anti-sanction NAME  shecan (default), electro, begzar, radar, none\n  \
         --socks-port N        SOCKS listener port (default 10808)\n  \
         --http-port N         HTTP listener port, or `off`\n  \
         --listen ADDR         listen address (default 127.0.0.1)\n  \
         --fragment            enable ClientHello fragmentation up front\n  \
         --no-ad-block         do not block advertising domains\n  \
         --no-assets           do not manage geosite/geoip downloads\n  \
         --asset-dir PATH      rule-set cache directory\n  \
         --clean-ip            measure Cloudflare edges and rank them\n  \
         --clean-ip-host NAME  fronted host for edge probes\n  \
         --clean-ip-ports LIST comma-separated ports (default 443,2053,8443)\n  \
         --clean-ip-seed N     candidate sampling seed (default 1)\n  \
         -o, --output FILE     write the config instead of printing it\n",
        env!("CARGO_PKG_VERSION")
    );
}

/// `zray preset iran <source>` — turn share links into a working Iran config.
///
/// The source may be a `vless://`-style link, a subscription file, or `-` for
/// standard input. Output is ordinary configuration JSON, so it can be edited
/// before use and checked with `zray check`.
fn cmd_preset(args: &[String]) -> Result<()> {
    let which = args.first().map(String::as_str).unwrap_or("iran");
    if which != "iran" {
        bail!("unknown preset {which:?}; the only preset is `iran`");
    }
    let rest = &args[1..];
    let source = rest
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .context("preset needs a share link, a subscription file, or `-` for stdin")?;

    let flag = |name: &str| -> Option<&String> {
        rest.iter()
            .position(|argument| argument == name)
            .and_then(|index| rest.get(index + 1))
    };
    let present = |name: &str| rest.iter().any(|argument| argument == name);

    let text = if source == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("reading standard input")?;
        buffer
    } else if source.contains("://") {
        source.clone()
    } else {
        std::fs::read_to_string(source).with_context(|| format!("reading {source}"))?
    };

    // Validate every link here so a bad one is reported with its index, then
    // emit the links themselves. The generated config keeps the link verbatim
    // rather than a re-encoding of it, so nothing can be lost in translation.
    let parsed = zero_config::parse_subscription(&text);
    let mut links = Vec::new();
    let mut failures = Vec::new();
    for (index, result) in parsed.iter().enumerate() {
        match result {
            Ok(link) => links.push(link.link.clone()),
            Err(error) => failures.push(format!("[{index}] {error}")),
        }
    }
    if links.is_empty() {
        for failure in &failures {
            eprintln!("{failure}");
        }
        bail!("no usable share links in the input");
    }
    for failure in &failures {
        eprintln!("skipped {failure}");
    }
    let outbounds = zero_config::presets::outbounds_from_links(&links);

    let mut preset = zero_config::IranPreset {
        outbounds,
        ..zero_config::IranPreset::default()
    };
    if let Some(value) = flag("--remote-dns") {
        preset.remote_dns = zero_config::RemoteDns::parse(value)
            .with_context(|| format!("unknown remote DNS preset {value:?}"))?;
    }
    if let Some(value) = flag("--local-dns") {
        preset.local_dns = zero_config::LocalDns::parse(value)
            .with_context(|| format!("unknown local DNS preset {value:?}"))?;
    }
    if let Some(value) = flag("--anti-sanction") {
        preset.anti_sanction_dns = zero_config::AntiSanctionDns::parse(value)
            .with_context(|| format!("unknown anti-sanction DNS preset {value:?}"))?;
    }
    if let Some(value) = flag("--socks-port") {
        preset.socks_port = value.parse().context("--socks-port must be a number")?;
    }
    if let Some(value) = flag("--http-port") {
        preset.http_port = if value.eq_ignore_ascii_case("off") {
            None
        } else {
            Some(
                value
                    .parse()
                    .context("--http-port must be a number or `off`")?,
            )
        };
    }
    if let Some(value) = flag("--listen") {
        preset.listen = value.clone();
    }
    if let Some(value) = flag("--asset-dir") {
        preset.asset_directory = Some(value.clone());
    }
    if present("--clean-ip") {
        // A bounded, repeatable candidate set: the observatory needs to
        // accumulate evidence about the *same* addresses across restarts, and
        // an unbounded set would make edge measurement a port scan.
        let ports: Vec<u16> = match flag("--clean-ip-ports") {
            Some(value) => value
                .split(',')
                .map(|port| port.trim().parse::<u16>())
                .collect::<Result<Vec<_>, _>>()
                .context("--clean-ip-ports must be a comma-separated port list")?,
            None => vec![443, 2053, 8443],
        };
        let seed: u64 = flag("--clean-ip-seed")
            .map(|value| value.parse())
            .transpose()
            .context("--clean-ip-seed must be a number")?
            .unwrap_or(1);
        if let Some(host) = flag("--clean-ip-host") {
            preset.clean_ip_host = host.clone();
        }
        preset.clean_ip_candidates =
            zero_net::clean_ip::cloudflare_candidates(&preset.clean_ip_host, &ports, 1, seed)
                .into_iter()
                .map(|candidate| candidate.address.to_string())
                .collect();
    }
    preset.fragment = present("--fragment");
    preset.block_ads = !present("--no-ad-block");
    preset.manage_assets = !present("--no-assets");

    let config = preset.build();
    // Emit only what this build can actually run: a preset that produces a
    // config the parser rejects is a bug, and printing it would hide that.
    let (_, diagnostics) = zero_config::parse_config(&config)
        .map_err(|error| anyhow::anyhow!("the generated preset is not valid: {error}"))?;
    for diagnostic in &diagnostics.diagnostics {
        eprintln!("note {}: {}", diagnostic.path, diagnostic.message);
    }

    let rendered = serde_json::to_string_pretty(&config)?;
    match flag("-o").or_else(|| flag("--output")) {
        Some(path) => {
            std::fs::write(path, format!("{rendered}\n"))
                .with_context(|| format!("writing {path}"))?;
            eprintln!("wrote {path}");
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// `zray assets refresh|check <config>` — operate the rule-set cache without
/// starting a proxy, so a user can fix rule-set problems before running.
fn cmd_assets(args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).unwrap_or("check");
    let path = args
        .get(1)
        .context("assets needs a config file path")?
        .clone();
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let mut configs = zero_config::parse_config_array(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    if configs.is_empty() {
        bail!("{path} contains no configurations");
    }
    let (_, config, _) = configs.remove(0);
    let assets = config
        .assets
        .clone()
        .context("this configuration has no `assets` section")?;
    let store = zero_runtime::asset_store_for(&assets);
    let specs = zero_runtime::asset_specs_for(&assets);
    if specs.is_empty() {
        bail!("this configuration lists no rule-set files");
    }
    println!("cache: {}", store.dir().display());

    match action {
        "check" => {
            let mut bad = 0usize;
            for spec in &specs {
                match store.load(spec) {
                    Ok(bytes) => {
                        let metadata = store.metadata(spec);
                        println!(
                            "  {:<16} ok    {:>9} bytes  {} entries  stale={}",
                            spec.name,
                            bytes.len(),
                            metadata
                                .entries
                                .map(|count| count.to_string())
                                .unwrap_or_else(|| "?".into()),
                            store.is_stale(spec)
                        );
                    }
                    Err(reason) => {
                        bad += 1;
                        println!("  {:<16} BAD   {reason}", spec.name);
                    }
                }
            }
            if bad > 0 {
                bail!("{bad} rule set(s) are missing or unusable; run `zray assets refresh`");
            }
            Ok(())
        }
        "refresh" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building the tokio runtime")?;
            let outcomes = runtime.block_on(store.refresh_all(&specs, true));
            let mut failed = 0usize;
            for (name, outcome) in &outcomes {
                match outcome {
                    zero_router::RefreshOutcome::Updated { bytes, entries } => {
                        println!("  {name:<16} updated  {bytes} bytes, {entries} entries");
                    }
                    zero_router::RefreshOutcome::Unchanged => {
                        println!("  {name:<16} unchanged");
                    }
                    zero_router::RefreshOutcome::Fresh => println!("  {name:<16} fresh"),
                    zero_router::RefreshOutcome::Failed { reasons } => {
                        failed += 1;
                        println!("  {name:<16} FAILED");
                        for reason in reasons {
                            println!("      {reason}");
                        }
                    }
                }
            }
            if failed > 0 {
                bail!("{failed} rule set(s) could not be refreshed");
            }
            Ok(())
        }
        other => bail!("unknown assets action {other:?}; use `check` or `refresh`"),
    }
}

fn cmd_check(args: &[String]) -> Result<()> {
    let path = PathBuf::from(args.first().context("check needs a file path")?);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    let trimmed = text.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        check_json(&text)
    } else {
        check_subscription(&text)
    }
}

fn check_json(text: &str) -> Result<()> {
    let configs = zero_config::parse_config_array(text).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("parsed {} config(s)\n", configs.len());
    let mut warned = 0usize;
    for (remark, cfg, out) in &configs {
        println!("── {remark}");
        println!(
            "   inbounds: {}   outbounds: {}   rules: {}   dns servers: {}",
            cfg.inbounds.len(),
            cfg.outbounds.len(),
            cfg.routing.rules.len(),
            cfg.dns.servers.len()
        );
        for o in cfg.outbounds.iter() {
            let mut line = format!(
                "   outbound {:<8} {:<9} {}/{}",
                o.tag,
                o.protocol.name(),
                o.stream.transport.name(),
                o.stream.security.name()
            );
            if let Some(f) = &o.stream.evasion.tcp_fragment {
                line.push_str(&format!(
                    "  fragment[{:?} {}-{}B {:?}-{:?}]",
                    f.packets, f.length.min, f.length.max, f.delay.min, f.delay.max
                ));
            }
            if !o.stream.evasion.udp_noise.is_empty() {
                line.push_str(&format!("  noise[{}]", o.stream.evasion.udp_noise.len()));
            }
            println!("{line}");
        }
        for d in &out.diagnostics {
            warned += 1;
            println!("   ! {}: {}", d.path, d.message);
        }
        println!();
    }
    println!("{} config(s) OK, {warned} diagnostic(s)", configs.len());
    Ok(())
}

fn check_subscription(text: &str) -> Result<()> {
    let results = zero_config::parse_subscription(text);
    let mut ok = 0usize;
    let mut failed = 0usize;

    for (i, r) in results.iter().enumerate() {
        match r {
            Ok(link) => {
                ok += 1;
                let o = &link.outbound;
                println!(
                    "[{i}] {:<28} {:<7} {}/{}",
                    truncate(&link.remark, 28),
                    o.protocol.name(),
                    o.stream.transport.name(),
                    o.stream.security.name()
                );
            }
            Err(e) => {
                failed += 1;
                println!("[{i}] ERROR: {e}");
            }
        }
    }
    println!("\n{ok} link(s) OK, {failed} failed");
    if failed > 0 {
        bail!("{failed} link(s) failed to parse");
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("ZRAY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("zray_cli=info,zero_runtime=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn cmd_run(args: &[String]) -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "-c" || arg == "--config" || arg == "-config" {
            if idx + 1 < args.len() {
                config_path = Some(PathBuf::from(&args[idx + 1]));
                idx += 2;
                continue;
            }
        } else if let Some(stripped) = arg.strip_prefix("--config=") {
            config_path = Some(PathBuf::from(stripped));
            idx += 1;
            continue;
        } else if let Some(stripped) = arg.strip_prefix("-config=") {
            config_path = Some(PathBuf::from(stripped));
            idx += 1;
            continue;
        } else if !arg.starts_with('-') && config_path.is_none() {
            config_path = Some(PathBuf::from(arg));
        }
        idx += 1;
    }

    let path = config_path.context(
        "run needs a config file path (use `zray run <file>` or `zray run --config=<file>`)",
    )?;
    let index: usize = args
        .iter()
        .position(|a| a == "-i" || a == "--index")
        .and_then(|i| args.get(i + 1))
        .map(|v| v.parse())
        .transpose()
        .context("index must be a number")?
        .unwrap_or(0);

    let management = args
        .iter()
        .position(|a| a == "--management")
        .and_then(|i| args.get(i + 1))
        .map(|value| {
            value
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("invalid management address {value:?}"))
        })
        .transpose()?;
    let token_env = args
        .iter()
        .position(|a| a == "--management-token-env")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "ZRAY_MANAGEMENT_TOKEN".into());
    let token_file = args
        .iter()
        .position(|a| a == "--management-token-file")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    // On a shutdown signal, finish in-flight sessions before exiting rather
    // than cutting live tunnels. 0 disables the wait (immediate exit).
    let drain_timeout: u64 = args
        .iter()
        .position(|a| a == "--drain-timeout")
        .and_then(|i| args.get(i + 1))
        .map(|v| v.parse())
        .transpose()
        .context("--drain-timeout must be a number of seconds")?
        .unwrap_or(10);

    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    let mut configs = zero_config::parse_config_array(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    if index >= configs.len() {
        bail!(
            "index {index} is out of range; the file has {} config(s)",
            configs.len()
        );
    }
    let (remark, config, out) = configs.remove(index);
    let generation = zero_config::RuntimeGeneration::compile(config, zero_core::GenerationId(1))
        .map_err(|error| anyhow::anyhow!("compiling configuration: {error}"))?;

    for d in &out.diagnostics {
        tracing::warn!(path = %d.path, "{}", d.message);
    }
    tracing::info!(remark = %remark, "starting");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;

    runtime.block_on(async move {
        use std::sync::Arc;
        let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }));

        let management_task = if let Some(listen) = management {
            let bearer_token = if let Some(path) = token_file.as_ref() {
                Some(
                    std::fs::read_to_string(path)
                        .with_context(|| format!("reading management token {}", path.display()))?
                        .trim()
                        .to_owned(),
                )
            } else {
                std::env::var(&token_env).ok()
            };
            let config = zero_runtime::api::ManagementConfig {
                listen,
                bearer_token: bearer_token.map(Into::into),
            };
            let management = zero_runtime::api::ManagementServer::new(config)
                .map_err(|error| anyhow::anyhow!("management API rejected: {error}"))?;
            let api_server = Arc::clone(&server);
            Some(tokio::spawn(async move {
                management
                    .run(api_server)
                    .await
                    .context("management API stopped")
            }))
        } else {
            None
        };

        let stats = Arc::clone(&server.stats);
        tokio::spawn(async move {
            let mut last = stats.snapshot();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let now = stats.snapshot();
                if now != last {
                    tracing::info!(
                        accepted = now.accepted,
                        ok = now.succeeded,
                        failed = now.failed,
                        up = now.uploaded,
                        down = now.downloaded,
                        "stats"
                    );
                    last = now;
                }
            }
        });

        let run = Arc::clone(&server);
        tokio::select! {
            r = run.run() => {
                r.context("server stopped")?;
            }
            r = async {
                match management_task {
                    Some(task) => {
                        task.await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))??;
                    }
                    None => std::future::pending::<()>().await,
                }
                Ok::<(), anyhow::Error>(())
            } => {
                r?;
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down (SIGINT)");
                drain_before_exit(&server, drain_timeout).await;
            }
            _ = async {
                #[cfg(unix)]
                {
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                        Ok(mut sigterm) => {
                            sigterm.recv().await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to register SIGTERM handler");
                            std::future::pending::<()>().await;
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                tracing::info!("shutting down (SIGTERM)");
                drain_before_exit(&server, drain_timeout).await;
            }
        }
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/// Wait for in-flight sessions to finish before returning from a shutdown
/// signal. The accept loops stop being polled once `run()`'s future is
/// dropped, so no new sessions start while this counts down.
async fn drain_before_exit(server: &std::sync::Arc<zero_runtime::Server>, timeout_secs: u64) {
    if timeout_secs == 0 {
        return;
    }
    let active = server.active_sessions();
    if active == 0 {
        return;
    }
    tracing::info!(active, timeout_secs, "draining active sessions before exit");
    let remaining = server
        .drain(std::time::Duration::from_secs(timeout_secs))
        .await;
    if remaining == 0 {
        tracing::info!("all sessions drained");
    } else {
        tracing::warn!(
            remaining,
            "drain timeout elapsed; exiting with sessions still active"
        );
    }
}
