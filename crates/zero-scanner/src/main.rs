use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zero_scanner::engine::{ScanEngine, ScanEngineConfig};
use zero_scanner::export::generate_exports;
use zero_scanner::ip::IpSource;
use zero_scanner::proxy::ProxyConfig;
use zero_scanner::speed::SpeedTester;
use zero_scanner::types::{ProbeConfig, ProbeMode, ProbeResult};
use zero_scanner::ui::{run_interactive_tui, TerminalUi};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "zero-ip-scanner",
    author = "Parsa",
    version = VERSION,
    about = "High-Performance Cloudflare IP Scanner in Rust"
)]
struct Cli {
    /// Probe mode: tcp, tls, or http
    #[arg(short = 'm', long, default_value = "http")]
    mode: String,

    /// Target port
    #[arg(short = 'p', long, default_value_t = 443)]
    port: u16,

    /// Concurrency (number of parallel workers)
    #[arg(short = 'c', long, default_value_t = 50)]
    concurrency: usize,

    /// Total candidate IPs to test (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 100)]
    count: usize,

    /// Timeout in seconds per probe attempt
    #[arg(short = 't', long, default_value_t = 5)]
    timeout: u64,

    /// Number of tries per IP to measure loss and jitter
    #[arg(long, default_value_t = 3)]
    tries: usize,

    /// Custom TLS SNI (empty = rotate well-known Cloudflare SNIs)
    #[arg(long)]
    sni: Option<String>,

    /// Require successful WebSocket upgrade for health
    #[arg(long, default_value_t = false)]
    ws: bool,

    /// WebSocket Host header (defaults to SNI)
    #[arg(long)]
    ws_host: Option<String>,

    /// WebSocket Path (defaults to /)
    #[arg(long)]
    ws_path: Option<String>,

    /// Download sample size in bytes for probe speed testing (0 = disabled)
    #[arg(long, default_value_t = 0)]
    speed_bytes: usize,

    /// Proxy share URL (vless://, trojan://, or vmess://) for Phase 2 validation
    #[arg(long)]
    proxy: Option<String>,

    /// Enable neighbor scanning around working IPs
    #[arg(long, default_value_t = false)]
    neighbors: bool,

    /// Scan IPv6 ranges
    #[arg(long, default_value_t = false)]
    v6: bool,

    /// Disable IPv4 ranges
    #[arg(long, default_value_t = false)]
    no_v4: bool,

    /// File containing custom IP addresses or CIDR ranges (one per line)
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,

    /// Directory to export endpoints, Clash YAML, Sing-box JSON, and subscription
    #[arg(short = 'o', long)]
    output_dir: Option<PathBuf>,

    /// Number of top endpoints to display in summary
    #[arg(long, default_value_t = 10)]
    top: usize,

    /// Launch interactive full-screen TUI (Ratatui Signal Desk)
    #[arg(long, default_value_t = false)]
    tui: bool,

    /// Run focused post-stop speed test on discovered green endpoints
    #[arg(long, default_value_t = false)]
    speed_test: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    raise_nofile_limit();

    let mode = cli.mode.parse::<ProbeMode>().unwrap_or_else(|e| {
        eprintln!("  [!] {}; using http", e);
        ProbeMode::Http
    });
    let mut custom_cidrs = Vec::new();

    if let Some(ref path) = cli.input {
        let content = fs::read_to_string(path);
        if let Err(ref e) = content {
            eprintln!("  [!] Could not read input file {:?}: {}", path, e);
        }
        if let Ok(content) = content {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    custom_cidrs.push(trimmed.to_string());
                }
            }
            if !cli.tui {
                println!(
                    "  [*] Loaded {} custom IP/CIDR entries from {:?}",
                    custom_cidrs.len(),
                    path
                );
            }
        }
    }

    let parsed_proxy = if let Some(ref p_str) = cli.proxy {
        match ProxyConfig::parse(p_str) {
            Ok(p) => {
                if !cli.tui {
                    println!(
                        "  [*] Phase 2 Proxy validation enabled: {} ({}:{})",
                        p.protocol, p.address, p.port
                    );
                }
                Some(p)
            }
            Err(e) => {
                eprintln!("  [!] Warning: Failed to parse proxy URL: {}", e);
                None
            }
        }
    } else {
        None
    };

    let use_v4 = !cli.no_v4;
    let use_v6 = cli.v6;
    // An input file replaces the built-in ranges instead of being diluted
    // into ~2M built-in addresses (the TUI's file mode already worked so).
    let use_builtin = cli.input.is_none();
    let ip_source = Arc::new(IpSource::new(use_v4, use_v6, &custom_cidrs, use_builtin));

    let probe_config = ProbeConfig {
        port: cli.port,
        mode,
        tries: cli.tries,
        timeout: Duration::from_secs(cli.timeout),
        sni: cli
            .sni
            .clone()
            .or_else(|| parsed_proxy.as_ref().map(|p| p.sni.clone())),
        speed_bytes: cli.speed_bytes,
        ws_host: cli
            .ws_host
            .clone()
            .or_else(|| parsed_proxy.as_ref().map(|p| p.host.clone())),
        ws_path: cli
            .ws_path
            .clone()
            .or_else(|| parsed_proxy.as_ref().map(|p| p.path.clone())),
        require_ws: cli.ws || parsed_proxy.as_ref().is_some_and(|p| p.transport == "ws"),
        check_dpi_hold: true,
        jitter_range_ms: (10, 30),
    };

    let engine_config = ScanEngineConfig {
        concurrency: cli.concurrency,
        target_count: cli.count,
        probe_config,
        neighbor_scan: cli.neighbors,
        proxy_config: parsed_proxy.clone(),
    };

    if cli.tui {
        run_interactive_tui().await?;
        return Ok(());
    }

    let engine = Arc::new(ScanEngine::new(engine_config, ip_source));
    let stats = engine.stats();
    // Standard CLI Output
    TerminalUi::print_banner(VERSION);
    println!(
        "  [*] Starting scan with concurrency {} against port {}...",
        cli.concurrency, cli.port
    );
    let progress_handle = TerminalUi::start_progress_printer(stats);

    // Ctrl+C stops the scan but still prints the summary and exports
    // what was found so far; a second Ctrl+C exits immediately.
    let cancel_engine = engine.clone();
    let ctrl_c = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\n  [*] Stopping scan (Ctrl+C again to quit immediately)...");
            cancel_engine.cancel();
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        }
    });

    let results = engine
        .run(|hit| {
            TerminalUi::print_hit(hit);
        })
        .await;

    progress_handle.abort();
    ctrl_c.abort();

    TerminalUi::print_summary(&results, cli.top);

    // Optional post-stop speed test on shortlist
    if cli.speed_test && !results.is_empty() {
        println!(
            "\n  [*] Running focused post-stop speed test on top {} endpoints...",
            cli.top.min(results.len())
        );
        let tester = SpeedTester::new(
            cli.sni
                .clone()
                .or_else(|| parsed_proxy.as_ref().map(|p| p.sni.clone())),
            if cli.speed_bytes == 0 {
                256 * 1024
            } else {
                cli.speed_bytes
            },
            Duration::from_secs(6),
        );
        let speed_shortlist: Vec<ProbeResult> = results.iter().take(cli.top).cloned().collect();
        let speed_results = tester.test_shortlist(&speed_shortlist, 4).await;

        println!(
            "================================================================================"
        );
        println!("  POST-STOP SPEED TEST RESULTS (RANKED BY THROUGHPUT)");
        println!(
            "================================================================================"
        );
        println!(
            "  {:<18} | {:<12} | {:<10} | {:<6}",
            "ENDPOINT", "DOWNLOAD", "TTFB", "COLO"
        );
        println!(
            "  ------------------------------------------------------------------------------"
        );
        for s in &speed_results {
            println!(
                "  {:<18} | {:>8.2} Mbps | {:>8.1}ms | {:<6}",
                format!("{}:{}", s.ip, s.port),
                s.download_mbps,
                s.ttfb_ms,
                s.colo.as_deref().unwrap_or("---")
            );
        }
        println!(
            "================================================================================"
        );
    }

    export_if_needed(&cli, &results, parsed_proxy.as_ref())?;

    Ok(())
}

/// Raises the soft open-file limit to the hard limit. Each in-flight probe
/// needs up to two sockets, and the common default soft limit of 1024 would
/// otherwise cap a scan at a few hundred workers (the engine also clamps its
/// concurrency to whatever limit is in force).
fn raise_nofile_limit() {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit/setrlimit only read/write the provided struct.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
                // macOS rejects values above OPEN_MAX even when the hard limit
                // is "unlimited"; keep a sane ceiling.
                lim.rlim_cur = lim.rlim_max.min(1 << 20);
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
        }
    }
}

fn export_if_needed(
    cli: &Cli,
    results: &[ProbeResult],
    parsed_proxy: Option<&ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref out_dir) = cli.output_dir {
        fs::create_dir_all(out_dir)?;
        let exports = generate_exports(results, parsed_proxy);

        let endpoints_path = out_dir.join("endpoints.txt");
        let clash_path = out_dir.join("clash.yaml");
        let singbox_path = out_dir.join("singbox.json");
        let sub_path = out_dir.join("subscription.txt");

        fs::write(&endpoints_path, &exports.endpoints_text)?;
        fs::write(&clash_path, &exports.clash_yaml)?;
        fs::write(&singbox_path, &exports.singbox_json)?;
        fs::write(&sub_path, &exports.subscription_base64)?;

        println!("\n  [*] Exported results to directory: {:?}", out_dir);
        println!("      - Endpoints:     {:?}", endpoints_path);
        println!("      - Clash YAML:    {:?}", clash_path);
        println!("      - Sing-box JSON: {:?}", singbox_path);
        println!("      - Subscription:  {:?}", sub_path);
    }
    Ok(())
}
