//! Structured failure classification.
//!
//! `std::io::Error` is not enough. The connection planner has to distinguish
//! "this network drops QUIC" from "this server is down" from "this path dies
//! after N bytes", and those decisions cannot be made from an errno.
//!
//! See RESEARCH-01 §28 and PLAN-02 §5.2.

use std::fmt;
use std::time::Duration;

use thiserror::Error;

/// How much a failure observation should be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Inferred, could be coincidence.
    Unknown,
    /// Consistent with interference but not proof.
    Likely,
    /// Directly observed and unambiguous.
    Confirmed,
}

/// The stage a connection reached before it failed.
///
/// This is the "ghost connectivity" ladder: a TCP handshake completing means
/// almost nothing on a filtered network, so confidence is only granted once
/// useful data has actually moved (RESEARCH-01 §27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Resolving,
    SocketConnected,
    TlsStarted,
    TlsCompleted,
    RequestSent,
    UploadConfirmed,
    FirstByteReceived,
    PayloadTransferred,
    BidirectionalConfirmed,
}

impl Stage {
    /// Whether reaching this stage justifies treating the path as working.
    pub fn is_useful_progress(self) -> bool {
        self >= Stage::FirstByteReceived
    }
}

/// The classified reason a connection attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    DnsTimeout,
    DnsNxDomain,
    DnsNoData,
    DnsMalformed,
    DnsSuspectedInterference,

    TcpTimeout,
    TcpReset,
    TcpUnreachable,
    TcpRefused,

    TlsTimeout,
    TlsAlert,
    TlsCertificateFailure,
    TlsHandshakeMalformed,

    Http403,
    Http421,
    Http5xx,
    HttpMalformed,
    H2ProtocolError,

    WebsocketRejected,
    WebsocketMalformed,

    UdpTimeout,
    UdpBlackhole,

    QuicHandshakeTimeout,
    QuicTransportError,

    RealityAuthFailure,
    RealityVersionFailure,
    RealityCertificateFailure,
    RealityFallback,

    ProtocolRejected,
    ServerRejected,
    NetworkChanged,
    LocalPolicy,
    Cancelled,
    Unknown,
}

impl FailureKind {
    /// Whether retrying the identical path could plausibly succeed.
    ///
    /// Auth and policy failures are deterministic; timeouts and resets are not.
    pub fn is_transient(self) -> bool {
        !matches!(
            self,
            FailureKind::DnsNxDomain
                | FailureKind::RealityAuthFailure
                | FailureKind::RealityVersionFailure
                | FailureKind::ProtocolRejected
                | FailureKind::LocalPolicy
                | FailureKind::Http403
        )
    }

    /// Whether this failure looks like deliberate interference rather than an
    /// ordinary network or server fault. Drives evasion escalation.
    pub fn suggests_interference(self) -> bool {
        matches!(
            self,
            FailureKind::DnsSuspectedInterference
                | FailureKind::TcpReset
                | FailureKind::TlsTimeout
                | FailureKind::UdpTimeout
                | FailureKind::UdpBlackhole
                | FailureKind::QuicHandshakeTimeout
                | FailureKind::TlsHandshakeMalformed
        )
    }

    pub fn as_str(self) -> &'static str {
        use FailureKind::*;
        match self {
            DnsTimeout => "DNS_TIMEOUT",
            DnsNxDomain => "DNS_NXDOMAIN",
            DnsNoData => "DNS_NODATA",
            DnsMalformed => "DNS_MALFORMED",
            DnsSuspectedInterference => "DNS_SUSPECTED_INTERFERENCE",
            TcpTimeout => "TCP_TIMEOUT",
            TcpReset => "TCP_RST",
            TcpUnreachable => "TCP_UNREACHABLE",
            TcpRefused => "TCP_REFUSED",
            TlsTimeout => "TLS_TIMEOUT",
            TlsAlert => "TLS_ALERT",
            TlsCertificateFailure => "TLS_CERTIFICATE_FAILURE",
            TlsHandshakeMalformed => "TLS_HANDSHAKE_MALFORMED",
            Http403 => "HTTP_403",
            Http421 => "HTTP_421",
            Http5xx => "HTTP_5XX",
            HttpMalformed => "HTTP_MALFORMED",
            H2ProtocolError => "H2_PROTOCOL_ERROR",
            WebsocketRejected => "WEBSOCKET_REJECTED",
            WebsocketMalformed => "WEBSOCKET_MALFORMED",
            UdpTimeout => "UDP_TIMEOUT",
            UdpBlackhole => "UDP_BLACKHOLE",
            QuicHandshakeTimeout => "QUIC_HANDSHAKE_TIMEOUT",
            QuicTransportError => "QUIC_TRANSPORT_ERROR",
            RealityAuthFailure => "REALITY_AUTH_FAILURE",
            RealityVersionFailure => "REALITY_VERSION_FAILURE",
            RealityCertificateFailure => "REALITY_CERTIFICATE_FAILURE",
            RealityFallback => "REALITY_FALLBACK",
            ProtocolRejected => "PROTOCOL_REJECTED",
            ServerRejected => "SERVER_REJECTED",
            NetworkChanged => "NETWORK_CHANGED",
            LocalPolicy => "LOCAL_POLICY",
            Cancelled => "CANCELLED",
            Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classified failure with the evidence the planner needs.
///
/// `bytes_at_failure` and `elapsed_at_failure` are the Iran-specific
/// discriminator from PLAN-02 §5.2: a reset after N bytes means
/// throughput-triggered DPI (fragment harder); a reset after T seconds with a
/// clean handshake means flow-timeout policy (change class). Same errno,
/// opposite remedies.
#[derive(Debug, Clone, Error)]
pub struct Failure {
    pub kind: FailureKind,
    pub stage: Stage,
    pub confidence: Confidence,
    pub bytes_at_failure: u64,
    pub elapsed_at_failure: Duration,
    pub detail: Option<String>,
}

impl Failure {
    pub fn new(kind: FailureKind, stage: Stage) -> Self {
        Self {
            kind,
            stage,
            confidence: Confidence::Unknown,
            bytes_at_failure: 0,
            elapsed_at_failure: Duration::ZERO,
            detail: None,
        }
    }

    pub fn with_confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_at_failure = bytes;
        self
    }

    pub fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed_at_failure = elapsed;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Classify an I/O error at a known stage.
    pub fn from_io(err: &std::io::Error, stage: Stage) -> Self {
        use std::io::ErrorKind as K;
        let kind = match err.kind() {
            K::TimedOut => match stage {
                Stage::Resolving => FailureKind::DnsTimeout,
                Stage::TlsStarted | Stage::TlsCompleted => FailureKind::TlsTimeout,
                _ => FailureKind::TcpTimeout,
            },
            K::ConnectionReset | K::ConnectionAborted => FailureKind::TcpReset,
            K::ConnectionRefused => FailureKind::TcpRefused,
            K::HostUnreachable | K::NetworkUnreachable | K::AddrNotAvailable => {
                FailureKind::TcpUnreachable
            }
            K::NetworkDown => FailureKind::NetworkChanged,
            K::UnexpectedEof => match stage {
                Stage::TlsStarted => FailureKind::TlsHandshakeMalformed,
                _ => FailureKind::TcpReset,
            },
            _ => FailureKind::Unknown,
        };
        // A reset we actually saw is confirmed; an inferred timeout is not.
        let confidence = match kind {
            FailureKind::TcpReset | FailureKind::TcpRefused | FailureKind::TcpUnreachable => {
                Confidence::Confirmed
            }
            FailureKind::Unknown => Confidence::Unknown,
            _ => Confidence::Likely,
        };
        Self::new(kind, stage)
            .with_confidence(confidence)
            .with_detail(err.to_string())
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {:?}", self.kind, self.stage)?;
        if self.bytes_at_failure > 0 {
            write!(f, " after {}B", self.bytes_at_failure)?;
        }
        if !self.elapsed_at_failure.is_zero() {
            write!(f, " in {:?}", self.elapsed_at_failure)?;
        }
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

/// The workspace error type.
#[derive(Debug, Error)]
pub enum Error {
    #[error("connection failed: {0}")]
    Failed(#[from] Failure),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }

    /// The classified failure, when there is one.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Error::Failed(f) => Some(f),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_is_confirmed_and_suggests_interference() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let f = Failure::from_io(&io, Stage::TlsStarted);
        assert_eq!(f.kind, FailureKind::TcpReset);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.kind.suggests_interference());
    }

    #[test]
    fn timeout_classification_depends_on_stage() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert_eq!(
            Failure::from_io(&io, Stage::Resolving).kind,
            FailureKind::DnsTimeout
        );
        assert_eq!(
            Failure::from_io(&io, Stage::TlsStarted).kind,
            FailureKind::TlsTimeout
        );
    }

    #[test]
    fn auth_failures_are_not_transient() {
        assert!(!FailureKind::RealityAuthFailure.is_transient());
        assert!(FailureKind::TcpTimeout.is_transient());
    }

    #[test]
    fn udp_timeout_is_interference_evidence() {
        // The planner has a dedicated UDP escape branch.  This predicate must
        // let an ordinary timeout reach it instead of silently holding the
        // current rung forever.
        assert!(FailureKind::UdpTimeout.suggests_interference());
    }

    #[test]
    fn socket_connected_is_not_useful_progress() {
        assert!(!Stage::SocketConnected.is_useful_progress());
        assert!(Stage::PayloadTransferred.is_useful_progress());
    }
}
