pub mod prober;
pub mod socket;
pub mod speed;
pub mod stability;
pub mod tls;
pub mod trace;
pub mod websocket;

pub use prober::{Prober, DEFAULT_SNI_POOL};
pub use socket::connect_tcp;
pub use speed::{
    probe_download, probe_download_detailed, DownloadSample, MAX_DOWNLOAD_SAMPLE_BYTES,
};
pub use stability::check_stability;
pub use tls::{connect_tls, make_tls_config, shared_tls_config};
pub use trace::probe_trace;
pub use websocket::probe_websocket_upgrade;

/// Cloudflare's plain-HTTP edge ports. Everything else it proxies speaks TLS.
pub const PLAIN_HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];

/// True when a Cloudflare edge serves plain HTTP (no TLS) on `port`.
pub fn is_plain_http_port(port: u16) -> bool {
    PLAIN_HTTP_PORTS.contains(&port)
}
