//! "Test my connection": what the network does to plain traffic, outside any
//! tunnel, and whether a running tunnel carries traffic.
//!
//! The same five checks as the Android app's `Diagnostics.kt`, in the same
//! words, so the two tell the same story:
//!
//! * **network** – there is a route out at all;
//! * **internet** – plain HTTP reaches Google's connectivity check (or is
//!   redirected to a block page or a login);
//! * **dns** – the resolver does not lie about filtered names;
//! * **tls** – a TLS hello with a filtered server name is treated like one
//!   with an ordinary name (DPI on the SNI);
//! * **tunnel** – a request through the local proxy of a running tunnel gets
//!   an answer.
//!
//! Nothing here sends more than a DNS query, one HTTP request and a few TLS
//! ClientHellos; no certificate is trusted for anything, since no application
//! data follows the handshakes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// How long any one probe waits.
pub const TIMEOUT: Duration = Duration::from_secs(6);

/// Sites filtered in Iran whose DNS answers are commonly poisoned.
const FILTERED_NAMES: [&str; 4] = [
    "www.youtube.com",
    "twitter.com",
    "www.instagram.com",
    "telegram.org",
];
/// A name that is not filtered, to tell "DNS is poisoned" from "DNS is down".
const CONTROL_NAME: &str = "www.google.com";
const PROBE_HOST: &str = "www.gstatic.com";
const PROBE_PATH: &str = "/generate_204";

/// A Cloudflare anycast address: any of them answers a ClientHello for any
/// name, so the two handshakes differ only in the name they carry.
const TLS_ADDRESS: &str = "104.16.123.96:443";
const CONTROL_SNI: &str = "www.cloudflare.com";
const FILTERED_SNI: &str = "www.youtube.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id {
    Network,
    Internet,
    Dns,
    Tls,
    Tunnel,
}

impl Id {
    pub const ALL: [Id; 5] = [Id::Network, Id::Internet, Id::Dns, Id::Tls, Id::Tunnel];

    /// The name shown for the check.
    pub fn name(self) -> &'static str {
        match self {
            Id::Network => "Network",
            Id::Internet => "Plain internet",
            Id::Dns => "DNS (filtered sites)",
            Id::Tls => "TLS server names (DPI)",
            Id::Tunnel => "Through the tunnel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Running,
    Ok,
    Warn,
    Bad,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: Id,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn new(id: Id, status: Status, detail: impl Into<String>) -> Self {
        Self {
            id,
            status,
            detail: detail.into(),
        }
    }
}

/// Run every check in order, telling `progress` each time one starts or
/// finishes. The tunnel check needs the local HTTP proxy of a running
/// connection and is skipped without one.
pub async fn run(http_proxy: Option<SocketAddr>, mut progress: impl FnMut(Check)) {
    for id in Id::ALL {
        progress(Check::new(id, Status::Running, ""));
        let result = match id {
            Id::Network => network().await,
            Id::Internet => internet().await,
            Id::Dns => dns().await,
            Id::Tls => tls().await,
            Id::Tunnel => match http_proxy {
                Some(proxy) => tunnel(proxy).await,
                None => Check::new(Id::Tunnel, Status::Skipped, "not connected"),
            },
        };
        progress(result);
    }
}

// --------------------------------------------------------------- the checks

/// A route out exists: a UDP socket can be aimed at a public address. Nothing
/// is sent.
pub async fn network() -> Check {
    let attempt = async {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect("1.1.1.1:53").await
    };
    match attempt.await {
        Ok(()) => Check::new(Id::Network, Status::Ok, ""),
        Err(error) => Check::new(Id::Network, Status::Bad, describe(&error)),
    }
}

/// Plain HTTP out of this network: works, is redirected to a block page, or
/// goes nowhere.
pub async fn internet() -> Check {
    let Ok(Some(address)) = resolve_one(PROBE_HOST, 80).await else {
        return Check::new(Id::Internet, Status::Bad, "name not resolved");
    };
    internet_at(address, TIMEOUT).await
}

pub async fn internet_at(address: SocketAddr, limit: Duration) -> Check {
    let request = format!(
        "GET {PROBE_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    );
    let attempt = async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        while head.len() < 4096 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, std::io::Error>(head)
    };
    match timeout(limit, attempt).await {
        Err(_) => Check::new(Id::Internet, Status::Bad, "timed out"),
        Ok(Err(error)) => Check::new(Id::Internet, Status::Bad, describe(&error)),
        Ok(Ok(head)) => classify_response(&head),
    }
}

fn classify_response(head: &[u8]) -> Check {
    let text = String::from_utf8_lossy(head);
    let status: u16 = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    match status {
        204 => Check::new(Id::Internet, Status::Ok, "HTTP 204"),
        300..=399 => {
            let location = text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("location").then(|| value.trim())
                })
                .unwrap_or("");
            Check::new(
                Id::Internet,
                Status::Warn,
                format!(
                    "redirected to {}",
                    location.chars().take(80).collect::<String>()
                ),
            )
        }
        0 => Check::new(Id::Internet, Status::Bad, "no HTTP answer"),
        other => Check::new(
            Id::Internet,
            Status::Warn,
            format!("HTTP {other} (a captive portal or a filter answered)"),
        ),
    }
}

/// Whether the network's resolver lies about filtered names.
pub async fn dns() -> Check {
    if resolve_all(CONTROL_NAME).await.is_none() {
        return Check::new(
            Id::Dns,
            Status::Bad,
            format!("{CONTROL_NAME}: name not resolved"),
        );
    }
    let mut poisoned = Vec::new();
    let mut failed = Vec::new();
    for name in FILTERED_NAMES {
        match resolve_all(name).await {
            None => failed.push(name),
            Some(addresses) => {
                if let Some(bogus) = addresses.iter().find(|a| is_bogus(**a)) {
                    poisoned.push(format!("{name} → {bogus}"));
                }
            }
        }
    }
    if !poisoned.is_empty() {
        Check::new(Id::Dns, Status::Bad, poisoned.join("; "))
    } else if !failed.is_empty() {
        Check::new(
            Id::Dns,
            Status::Warn,
            format!("no answer for {}", failed.join(", ")),
        )
    } else {
        Check::new(
            Id::Dns,
            Status::Ok,
            format!(
                "{} filtered names resolve to real addresses",
                FILTERED_NAMES.len()
            ),
        )
    }
}

/// Answers a poisoning resolver gives: the block-page range, private,
/// loopback, unspecified, carrier NAT and benchmarking ranges.
pub fn is_bogus(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
    }
}

/// Deep packet inspection of the TLS server name: the same address is greeted
/// twice, once with an ordinary name and once with a filtered one. A reset or
/// silence only for the filtered name is the DPI box.
pub async fn tls() -> Check {
    let address: SocketAddr = TLS_ADDRESS.parse().expect("a fixed address");
    tls_at(address, CONTROL_SNI, FILTERED_SNI, TIMEOUT).await
}

pub async fn tls_at(address: SocketAddr, control: &str, filtered: &str, limit: Duration) -> Check {
    let (control_ok, control_note) = handshake_at(address, control, limit).await;
    let (filtered_ok, filtered_note) = handshake_at(address, filtered, limit).await;
    if !control_ok {
        Check::new(
            Id::Tls,
            Status::Bad,
            format!("TLS to Cloudflare fails even for {control}: {control_note}"),
        )
    } else if !filtered_ok {
        Check::new(
            Id::Tls,
            Status::Bad,
            format!("SNI filtering: {filtered} {filtered_note}"),
        )
    } else {
        Check::new(Id::Tls, Status::Ok, "no SNI filtering seen")
    }
}

/// (reached the server, what happened). A certificate or alert error still
/// means the server answered.
pub async fn handshake_at(address: SocketAddr, sni: &str, limit: Duration) -> (bool, String) {
    let Ok(name) = ServerName::try_from(sni.to_string()) else {
        return (false, "not a valid name".into());
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(hello_only_config()));
    let attempt = async {
        let stream = TcpStream::connect(address).await?;
        connector.connect(name, stream).await.map(|_| ())
    };
    match timeout(limit, attempt).await {
        Err(_) => (false, "timed out (no answer)".into()),
        Ok(Ok(())) => (true, "handshake completed".into()),
        Ok(Err(error)) => match error.kind() {
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe => {
                (false, "connection reset during the handshake".into())
            }
            std::io::ErrorKind::TimedOut => (false, "timed out (no answer)".into()),
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable => (false, describe(&error)),
            // An alert or a certificate the client dislikes: something answered.
            _ => (true, "server answered".into()),
        },
    }
}

/// Plain HTTP through the local proxy of a running tunnel: `CONNECT` to a
/// well-known host, a real TLS handshake with the certificate checked (what a
/// browser needs), then one request.
pub async fn tunnel(proxy: SocketAddr) -> Check {
    let started = Instant::now();
    let attempt = async {
        let mut stream = TcpStream::connect(proxy).await.map_err(|e| describe(&e))?;
        let connect =
            format!("CONNECT {PROBE_HOST}:443 HTTP/1.1\r\nHost: {PROBE_HOST}:443\r\n\r\n");
        stream
            .write_all(connect.as_bytes())
            .await
            .map_err(|e| describe(&e))?;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 2048 {
            let n = stream.read(&mut byte).await.map_err(|e| describe(&e))?;
            if n == 0 {
                return Err("the proxy closed the connection".to_string());
            }
            head.push(byte[0]);
        }
        let reply = String::from_utf8_lossy(&head);
        if !reply.starts_with("HTTP/1.1 200") && !reply.starts_with("HTTP/1.0 200") {
            let line = reply.lines().next().unwrap_or("").to_string();
            return Err(format!("the proxy answered: {line}"));
        }
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = ServerName::try_from(PROBE_HOST.to_string()).map_err(|e| e.to_string())?;
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|e| format!("TLS through the tunnel failed: {e}"))?;
        let request = format!(
            "GET {PROBE_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        );
        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| describe(&e))?;
        let mut answer = vec![0u8; 512];
        let n = tls.read(&mut answer).await.map_err(|e| describe(&e))?;
        let text = String::from_utf8_lossy(&answer[..n]).to_string();
        Ok(text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0))
    };
    match timeout(TIMEOUT, attempt).await {
        Err(_) => Check::new(Id::Tunnel, Status::Bad, "timed out"),
        Ok(Err(error)) => Check::new(Id::Tunnel, Status::Bad, error),
        Ok(Ok(code)) => {
            let ms = started.elapsed().as_millis();
            if code == 204 {
                Check::new(Id::Tunnel, Status::Ok, format!("HTTP 204 in {ms} ms"))
            } else {
                Check::new(Id::Tunnel, Status::Warn, format!("HTTP {code} in {ms} ms"))
            }
        }
    }
}

// ----------------------------------------------------------------- helpers

async fn resolve_all(name: &str) -> Option<Vec<IpAddr>> {
    let found: Vec<IpAddr> = timeout(TIMEOUT, tokio::net::lookup_host((name, 443)))
        .await
        .ok()?
        .ok()?
        .map(|address| address.ip())
        .collect();
    (!found.is_empty()).then_some(found)
}

async fn resolve_one(name: &str, port: u16) -> Result<Option<SocketAddr>, std::io::Error> {
    match timeout(TIMEOUT, tokio::net::lookup_host((name, port))).await {
        Err(_) => Ok(None),
        Ok(Err(error)) => Err(error),
        Ok(Ok(mut addresses)) => Ok(addresses.next()),
    }
}

/// An error in the words a person can act on.
pub fn describe(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::TimedOut => "timed out".into(),
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::ConnectionReset => "connection reset".into(),
        std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
            "network unreachable".into()
        }
        _ => error.to_string().chars().take(80).collect(),
    }
}

/// A client that says hello and accepts whatever answers; it is used only to
/// see whether a server answers, and sends nothing afterwards.
fn hello_only_config() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct AcceptAll(rustls::crypto::WebPkiSupportedAlgorithms);
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(algorithms)))
        .with_no_client_auth()
}

// ---------------------------------------------------------- reading a result

/// What a finished set of checks says, nearest the phone first: the same
/// order the Android path map reads them in. The words belong to the screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    None,
    NoNetwork,
    NoInternet,
    Redirected,
    FakeDns,
    NameFilter,
    NoServer,
}

/// The first thing wrong on the direct path, or on the tunnel.
pub fn problem(checks: &[Check]) -> Problem {
    let of = |id: Id| checks.iter().find(|c| c.id == id).map(|c| c.status);
    match () {
        _ if of(Id::Network) == Some(Status::Bad) => Problem::NoNetwork,
        _ if of(Id::Internet) == Some(Status::Bad) => Problem::NoInternet,
        _ if of(Id::Internet) == Some(Status::Warn) => Problem::Redirected,
        _ if matches!(of(Id::Dns), Some(Status::Bad | Status::Warn)) => Problem::FakeDns,
        _ if of(Id::Tls) == Some(Status::Bad) => Problem::NameFilter,
        _ if of(Id::Tunnel) == Some(Status::Bad) => Problem::NoServer,
        _ => Problem::None,
    }
}

/// Whether every check has finished.
pub fn finished(checks: &[Check]) -> bool {
    !checks.is_empty()
        && checks
            .iter()
            .all(|c| !matches!(c.status, Status::Pending | Status::Running))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn check(id: Id, status: Status) -> Check {
        Check::new(id, status, "")
    }

    fn all(status: [Status; 5]) -> Vec<Check> {
        Id::ALL
            .iter()
            .zip(status)
            .map(|(id, s)| check(*id, s))
            .collect()
    }

    use Status::{Bad, Ok as Good, Skipped, Warn};

    #[test]
    fn the_first_problem_nearest_the_phone_is_the_one_reported() {
        assert_eq!(
            problem(&all([Bad, Bad, Bad, Bad, Skipped])),
            Problem::NoNetwork
        );
        assert_eq!(
            problem(&all([Good, Bad, Bad, Bad, Skipped])),
            Problem::NoInternet
        );
        assert_eq!(
            problem(&all([Good, Warn, Bad, Good, Skipped])),
            Problem::Redirected
        );
        assert_eq!(
            problem(&all([Good, Good, Bad, Bad, Skipped])),
            Problem::FakeDns
        );
        assert_eq!(
            problem(&all([Good, Good, Warn, Good, Skipped])),
            Problem::FakeDns
        );
        assert_eq!(
            problem(&all([Good, Good, Good, Bad, Good])),
            Problem::NameFilter
        );
        assert_eq!(
            problem(&all([Good, Good, Good, Good, Bad])),
            Problem::NoServer
        );
        assert_eq!(
            problem(&all([Good, Good, Good, Good, Skipped])),
            Problem::None
        );
    }

    #[test]
    fn a_test_is_finished_only_when_nothing_is_pending_or_running() {
        assert!(!finished(&[]));
        assert!(!finished(&all([
            Good,
            Status::Running,
            Status::Pending,
            Status::Pending,
            Skipped
        ])));
        assert!(finished(&all([Good, Good, Good, Good, Skipped])));
    }

    #[test]
    fn poisoned_answers_are_recognised_and_real_ones_are_not() {
        for bogus in [
            "10.10.34.35",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "100.64.0.9",
            "198.18.0.1",
            "::1",
            "::",
        ] {
            assert!(is_bogus(bogus.parse().unwrap()), "{bogus}");
        }
        for real in ["142.250.184.14", "104.16.123.96", "2606:4700::1111"] {
            assert!(!is_bogus(real.parse().unwrap()), "{real}");
        }
    }

    #[test]
    fn a_response_is_sorted_into_works_redirected_or_odd() {
        assert_eq!(
            classify_response(b"HTTP/1.1 204 No Content\r\n\r\n").status,
            Good
        );
        let redirected =
            classify_response(b"HTTP/1.1 302 Found\r\nLocation: http://10.10.34.34/\r\n\r\n");
        assert_eq!(redirected.status, Warn);
        assert!(redirected.detail.contains("10.10.34.34"));
        assert_eq!(
            classify_response(b"HTTP/1.1 403 Forbidden\r\n\r\n").status,
            Warn
        );
        assert_eq!(classify_response(b"garbage").status, Bad);
        assert_eq!(classify_response(b"").status, Bad);
    }

    async fn serve_once(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(reply).await;
            }
        });
        address
    }

    #[tokio::test]
    async fn plain_http_is_told_apart_from_a_block_page_and_from_silence() {
        let ok = serve_once(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        assert_eq!(internet_at(ok, Duration::from_secs(2)).await.status, Good);
        let block = serve_once(b"HTTP/1.1 302 Found\r\nLocation: http://10.10.34.34\r\n\r\n").await;
        assert_eq!(
            internet_at(block, Duration::from_secs(2)).await.status,
            Warn
        );
        // A server that accepts and never answers.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });
        let result = internet_at(address, Duration::from_millis(200)).await;
        assert_eq!(result.status, Bad);
        assert_eq!(result.detail, "timed out");
    }

    #[tokio::test]
    async fn a_reset_during_the_handshake_is_interference_and_an_alert_is_an_answer() {
        // Accept and slam the door: what a DPI box does to a hello it dislikes.
        let resetter = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reset_at = resetter.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = resetter.accept().await {
                drop(stream);
            }
        });
        let (reached, note) =
            handshake_at(reset_at, "www.youtube.com", Duration::from_secs(2)).await;
        assert!(!reached, "{note}");
        assert!(note.contains("reset"), "{note}");

        // A server that answers the hello with a fatal alert is a server.
        let alert = serve_once(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
        let (reached, note) = handshake_at(alert, "www.youtube.com", Duration::from_secs(2)).await;
        assert!(reached, "{note}");
    }

    #[tokio::test]
    async fn sni_filtering_is_reported_when_only_the_filtered_name_is_cut() {
        // One listener that resets when the hello names the filtered site and
        // answers with an alert otherwise.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut hello = vec![0u8; 2048];
                let n = stream.read(&mut hello).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&hello[..n]).to_string();
                if text.contains("blocked.example") {
                    drop(stream);
                } else {
                    let _ = stream
                        .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
                        .await;
                }
            }
        });
        let result = tls_at(
            address,
            "fine.example",
            "blocked.example",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result.status, Bad);
        assert!(
            result.detail.starts_with("SNI filtering"),
            "{}",
            result.detail
        );
        let clean = tls_at(
            address,
            "fine.example",
            "also-fine.example",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(clean.status, Good, "{}", clean.detail);
        // Even the ordinary name failing is said as such, not as filtering.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_at = dead.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = dead.accept().await {
                drop(stream);
            }
        });
        let broken = tls_at(
            dead_at,
            "fine.example",
            "blocked.example",
            Duration::from_secs(2),
        )
        .await;
        assert!(
            broken.detail.starts_with("TLS to Cloudflare fails"),
            "{}",
            broken.detail
        );
    }

    #[tokio::test]
    async fn the_tunnel_check_says_what_the_proxy_did() {
        let refusing = serve_once(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        let result = tunnel(refusing).await;
        assert_eq!(result.status, Bad);
        assert!(result.detail.contains("502"), "{}", result.detail);
        let nothing: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(tunnel(nothing).await.status, Bad);
    }

    #[tokio::test]
    async fn without_a_running_tunnel_that_check_is_skipped_and_every_check_reports_twice() {
        let mut seen: Vec<Check> = Vec::new();
        // The probes reach the real network, which a test cannot rely on, so
        // only the shape of the report is checked.
        tokio::time::timeout(Duration::from_secs(90), run(None, |c| seen.push(c)))
            .await
            .expect("the checks finish within their own timeouts");
        assert_eq!(seen.len(), 10);
        for pair in seen.chunks(2) {
            assert_eq!(pair[0].id, pair[1].id);
            assert_eq!(pair[0].status, Status::Running);
            assert_ne!(pair[1].status, Status::Running);
        }
        assert_eq!(seen.last().unwrap().status, Skipped);
    }
}
