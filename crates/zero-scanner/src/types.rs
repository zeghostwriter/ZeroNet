use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeMode {
    Tcp,
    Tls,
    Http,
}

impl std::fmt::Display for ProbeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeMode::Tcp => write!(f, "tcp"),
            ProbeMode::Tls => write!(f, "tls"),
            ProbeMode::Http => write!(f, "http"),
        }
    }
}

impl std::str::FromStr for ProbeMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(ProbeMode::Tcp),
            "tls" => Ok(ProbeMode::Tls),
            "http" | "https" => Ok(ProbeMode::Http),
            _ => Err(format!("Unknown probe mode: {}", s)),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub struct ResultFlags: u16 {
        const TCP_OK     = 1 << 0;
        const TLS_OK     = 1 << 1;
        const HTTP_OK    = 1 << 2;
        const WS_OK      = 1 << 3;
        const STABLE_OK  = 1 << 4;
        const PROXY_OK   = 1 << 5;
        const SPEED_OK   = 1 << 6;
        const NEIGHBOR   = 1 << 7;
    }
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub port: u16,
    pub mode: ProbeMode,
    pub tries: usize,
    pub timeout: Duration,
    pub sni: Option<String>,
    pub speed_bytes: usize,
    pub ws_host: Option<String>,
    pub ws_path: Option<String>,
    pub require_ws: bool,
    pub check_dpi_hold: bool,
    pub jitter_range_ms: (u64, u64),
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            port: 443,
            mode: ProbeMode::Http,
            tries: 4,
            timeout: Duration::from_secs(5),
            sni: None,
            speed_bytes: 0,
            ws_host: None,
            ws_path: Some("/".to_string()),
            require_ws: false,
            check_dpi_hold: false,
            jitter_range_ms: (10, 40),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub mode: ProbeMode,
    pub latencies_ms: Vec<f64>,
    pub flags: ResultFlags,
    pub http_status: u16,
    pub colo: Option<String>,
    pub throughput_mbps: f64,
    pub isp: Option<String>,
    pub asn: Option<u32>,
}

impl ProbeResult {
    pub fn is_healthy(&self, require_ws: bool) -> bool {
        match self.mode {
            ProbeMode::Tcp => self.flags.contains(ResultFlags::TCP_OK),
            ProbeMode::Tls => self.flags.contains(ResultFlags::TLS_OK),
            ProbeMode::Http => {
                let base = self.flags.contains(ResultFlags::HTTP_OK)
                    && (self.http_status >= 200 && self.http_status < 400
                        || self.http_status == 301
                        || self.http_status == 403)
                    && self.colo.is_some();
                if require_ws {
                    base && self.flags.contains(ResultFlags::WS_OK)
                } else {
                    base
                }
            }
        }
    }

    pub fn packet_loss_percent(&self) -> f64 {
        if self.latencies_ms.is_empty() {
            return 100.0;
        }
        let failed = self.latencies_ms.iter().filter(|&&l| l <= 0.0).count();
        (failed as f64 / self.latencies_ms.len() as f64) * 100.0
    }

    pub fn avg_latency_ms(&self) -> f64 {
        let (sum, n) = self
            .latencies_ms
            .iter()
            .filter(|&&l| l > 0.0)
            .fold((0.0, 0usize), |(s, n), &l| (s + l, n + 1));
        if n == 0 {
            return 0.0;
        }
        sum / n as f64
    }

    pub fn min_latency_ms(&self) -> f64 {
        self.latencies_ms
            .iter()
            .copied()
            .filter(|&l| l > 0.0)
            .fold(f64::MAX, f64::min)
            .min(9999.0)
    }

    pub fn max_latency_ms(&self) -> f64 {
        self.latencies_ms
            .iter()
            .copied()
            .filter(|&l| l > 0.0)
            .fold(0.0, f64::max)
    }

    pub fn jitter_ms(&self) -> f64 {
        let n = self.latencies_ms.iter().filter(|&&l| l > 0.0).count();
        if n < 2 {
            return 0.0;
        }
        let avg = self.avg_latency_ms();
        let variance = self
            .latencies_ms
            .iter()
            .filter(|&&l| l > 0.0)
            .map(|&x| (x - avg).powi(2))
            .sum::<f64>()
            / n as f64;
        variance.sqrt()
    }
}

#[derive(Default)]
pub struct AtomicStats {
    pub tested: AtomicU64,
    pub healthy: AtomicU64,
    pub failed: AtomicU64,
    pub in_flight: AtomicU64,
    pub start_time: Option<Instant>,
}

impl AtomicStats {
    pub fn new() -> Self {
        Self {
            tested: AtomicU64::new(0),
            healthy: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            start_time: Some(Instant::now()),
        }
    }

    pub fn record_start(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Undoes `record_start` for a probe that was dropped (scan cancelled)
    /// before it produced a verdict.
    pub fn record_abandoned(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_finish(&self, healthy: bool) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.tested.fetch_add(1, Ordering::Relaxed);
        if healthy {
            self.healthy.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> (u64, u64, u64, u64, f64) {
        let tested = self.tested.load(Ordering::Relaxed);
        let healthy = self.healthy.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let in_flight = self.in_flight.load(Ordering::Relaxed);
        let elapsed = self.start_time.map_or(0.001, |t| t.elapsed().as_secs_f64());
        let speed = if elapsed > 0.0 {
            tested as f64 / elapsed
        } else {
            0.0
        };
        (tested, healthy, failed, in_flight, speed)
    }
}
