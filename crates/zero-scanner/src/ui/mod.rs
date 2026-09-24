pub mod diagnostics;
pub mod file_browser;
pub mod tui;

use crate::types::{AtomicStats, ProbeResult};
use std::sync::Arc;
use std::time::Duration;

pub use diagnostics::{run_diagnostics, DiagnosticReport};
pub use file_browser::{scan_for_ip_files, IpFileInfo};
pub use tui::{run_interactive_tui, TuiApp, TuiPage};

pub struct TerminalUi;

impl TerminalUi {
    pub fn print_banner(version: &str) {
        println!(
            "================================================================================"
        );
        println!(
            "  ZERO-IP-SCANNER v{} - Ultra-Fast Cloudflare Endpoint Scanner",
            version
        );
        println!("  Features: Cloudflare-style DNS cache, DPI idle-hold, WS probe, VLESS/Trojan");
        println!(
            "================================================================================"
        );
    }

    pub fn print_hit(res: &ProbeResult) {
        let colo_str = res.colo.as_deref().unwrap_or("---");
        let isp_str = if let Some(ref isp) = res.isp {
            isp.clone()
        } else if let Some(asn) = res.asn {
            format!("AS{}", asn)
        } else {
            "Cloudflare".to_string()
        };

        println!(
            "  [+] {:<15}:{:>4} | {:>6.1}ms | Loss: {:>2.0}% | Colo: {:<4} | {}",
            res.ip,
            res.port,
            res.avg_latency_ms(),
            res.packet_loss_percent(),
            colo_str,
            isp_str
        );
    }

    pub fn start_progress_printer(stats: Arc<AtomicStats>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                let (tested, healthy, failed, in_flight, speed) = stats.snapshot();
                eprint!(
                    "\r  [SCANNING] Tested: {} | Healthy: {} | Failed: {} | In-Flight: {} | Rate: {:.1} ip/s    ",
                    tested, healthy, failed, in_flight, speed
                );
            }
        })
    }

    pub fn print_summary(results: &[ProbeResult], top_k: usize) {
        println!("\n");
        println!(
            "================================================================================"
        );
        println!(
            "  TOP {} HEALTHY CLOUDFLARE ENDPOINTS",
            top_k.min(results.len())
        );
        println!(
            "================================================================================"
        );
        println!(
            "  {:<18} | {:<8} | {:<8} | {:<8} | {:<6} | {:<20}",
            "ENDPOINT", "LATENCY", "LOSS", "JITTER", "COLO", "ISP/ASN"
        );
        println!(
            "  ------------------------------------------------------------------------------"
        );

        for r in results.iter().take(top_k) {
            let ep = format!("{}:{}", r.ip, r.port);
            let lat = format!("{:.1}ms", r.avg_latency_ms());
            let loss = format!("{:.0}%", r.packet_loss_percent());
            let jitter = format!("{:.1}ms", r.jitter_ms());
            let colo = r.colo.as_deref().unwrap_or("---");
            let isp = if let Some(ref s) = r.isp {
                s.clone()
            } else if let Some(asn) = r.asn {
                format!("AS{}", asn)
            } else {
                "Cloudflare".to_string()
            };

            println!(
                "  {:<18} | {:<8} | {:<8} | {:<8} | {:<6} | {:<20}",
                ep, lat, loss, jitter, colo, isp
            );
        }
        println!(
            "================================================================================"
        );
    }
}
