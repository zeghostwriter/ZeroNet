pub mod dns;
pub mod engine;
pub mod export;
pub mod ip;
pub mod meta;
pub mod probe;
pub mod proxy;
pub mod speed;
pub mod types;
#[cfg(feature = "tui")]
pub mod ui;

pub use dns::{CompactDnsEntry, DnsCache, DnsCacheKey, FastResolver};
pub use engine::{ScanEngine, ScanEngineConfig};
pub use export::{generate_exports, ExportBundle};
pub use ip::{neighbors_around, IpSource, SubnetV4, SubnetV6};
pub use meta::{lookup_cymru_asn, lookup_iranian_isp};
pub use probe::{connect_tcp, connect_tls, Prober};
pub use proxy::{
    build_xray_json, find_xray_binary, validate_proxy, ProxyConfig, ProxyValidationResult,
    XrayRunner,
};
pub use speed::{SpeedTestResult, SpeedTester};
pub use types::{AtomicStats, ProbeConfig, ProbeMode, ProbeResult, ResultFlags};
#[cfg(feature = "tui")]
pub use ui::{
    run_diagnostics, run_interactive_tui, scan_for_ip_files, DiagnosticReport, IpFileInfo,
    TerminalUi, TuiApp, TuiPage,
};
