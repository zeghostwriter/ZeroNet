//! How a QUIC carrier's socket and transport are shaped beyond what its
//! protocol asks for: obfuscated datagrams, a server port that moves,
//! congestion control and the QUIC limits Xray's `quicParams` names.
//!
//! How this works: a [`QuicShape`] is plain data the runtime fills in from a
//! configuration. [`QuicShape::wrap_socket`] builds the endpoint's socket
//! (UDP, then Salamander, then port hopping, so QUIC at the top sees one
//! server address and the wire sees obfuscated datagrams to a moving port) and
//! [`QuicShape::transport`] builds the QUIC transport configuration with the
//! limits and the congestion controller. An empty shape changes nothing.
//!
//! The rule it keeps: the same shape always makes the same socket, so a
//! connection that moves to a new network (a rebind) keeps its obfuscation
//! and its hopping.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::congestion::{BbrConfig, ControllerFactory, NewRenoConfig};
use quinn::{AsyncUdpSocket, Runtime, TransportConfig, VarInt};

use crate::hop::{Hop, HoppingSocket};
use crate::quic_cc::{CongestionHandle, SwitchableFactory};
use crate::salamander::Salamander;

/// How the carrier decides how fast to send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    /// The carrier's own choice (quinn's default for Hysteria 2 today).
    #[default]
    Default,
    Reno,
    Bbr,
    /// Send at the configured rate when the peer agrees to receive it.
    Brutal,
    /// Send at the configured rate whatever the peer says.
    ForceBrutal,
}

/// The QUIC limits and rates a link can set. `None` and zero mean "leave it".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuicParams {
    pub congestion: Congestion,
    /// Bytes per second this end may send at under Brutal.
    pub up_bytes_per_sec: u64,
    /// Bytes per second this end asks the peer to send at.
    pub down_bytes_per_sec: u64,
    pub init_stream_window: Option<u32>,
    pub max_stream_window: Option<u32>,
    pub init_connection_window: Option<u32>,
    pub max_connection_window: Option<u32>,
    pub max_idle: Option<Duration>,
    pub keep_alive: Option<Duration>,
    pub disable_mtu_discovery: bool,
    pub max_incoming_streams: Option<u32>,
}

/// Everything about shaping one QUIC carrier. See the module docs.
#[derive(Clone, Debug, Default)]
pub struct QuicShape {
    pub salamander: Option<Salamander>,
    pub hop: Option<Hop>,
    pub params: QuicParams,
}

impl QuicShape {
    /// Nothing asked for.
    pub fn is_plain(&self) -> bool {
        self.salamander.is_none() && self.hop.is_none() && self.params == QuicParams::default()
    }

    /// Text that differs whenever the shape does, for a pool key. The
    /// obfuscation password is a secret, so it goes in as a hash.
    pub fn key_text(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // Debug of `Salamander` hides the password, so hash it by what it
        // does: its obfuscation of a fixed salt and text.
        if let Some(salamander) = &self.salamander {
            let mut probe = Vec::new();
            salamander.obfuscate_with_fixed_salt(&mut probe);
            probe.hash(&mut hasher);
        }
        format!(
            "shape:{:016x}:{:?}:{:?}",
            hasher.finish(),
            self.hop,
            self.params
        )
    }

    /// The endpoint's socket for a connection to `server`: a fresh UDP socket
    /// that the platform keeps out of a VPN, with Salamander over it, and the
    /// port hopper over that when a plan is set (which then opens a new
    /// socket for every stay). Call it inside the runtime that will drive
    /// the endpoint.
    pub fn open_socket(&self, server: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let bind: SocketAddr = if server.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let salamander = self.salamander.clone();
        let open = move || -> io::Result<Arc<dyn AsyncUdpSocket>> {
            let socket = zero_core::platform::bind_protected_udp(bind)?;
            let mut socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            if let Some(salamander) = &salamander {
                socket = crate::salamander::ObfuscatedSocket::wrap(socket, salamander.clone());
            }
            Ok(socket)
        };
        match &self.hop {
            Some(hop) => HoppingSocket::open(Box::new(open), hop.clone(), server),
            None => open(),
        }
    }

    /// The QUIC transport configuration: the carrier's `idle` timeout and
    /// `keep_alive` unless the shape names its own, with the limits and the
    /// congestion controller applied. The handle, when there is one, sets the
    /// Brutal rate once the peer has agreed to it.
    pub fn transport(
        &self,
        idle: Duration,
        keep_alive: Option<Duration>,
    ) -> (TransportConfig, Option<CongestionHandle>) {
        let params = &self.params;
        let mut config = crate::relay::quic_transport(
            params.max_idle.unwrap_or(idle),
            params.keep_alive.or(keep_alive),
        );
        let window = |value: u32| VarInt::from_u32(value);
        if let Some(value) = params.max_stream_window.or(params.init_stream_window) {
            config.stream_receive_window(window(value));
        }
        if let Some(value) = params
            .max_connection_window
            .or(params.init_connection_window)
        {
            config.receive_window(window(value));
            config.send_window(u64::from(value));
        }
        if params.disable_mtu_discovery {
            config.mtu_discovery_config(None);
        }
        if let Some(streams) = params.max_incoming_streams {
            config.max_concurrent_bidi_streams(streams.into());
        }
        // Brutal that the peer did not agree to falls back to BBR, as
        // Hysteria's does; the other choices stand for themselves.
        let inner: Option<Arc<dyn ControllerFactory + Send + Sync>> = match params.congestion {
            Congestion::Reno => Some(Arc::new(NewRenoConfig::default())),
            Congestion::Bbr | Congestion::Brutal | Congestion::ForceBrutal => {
                Some(Arc::new(BbrConfig::default()))
            }
            Congestion::Default => None,
        };
        let brutal = matches!(
            params.congestion,
            Congestion::Brutal | Congestion::ForceBrutal
        );
        if brutal {
            let (factory, handle) = SwitchableFactory::new(inner);
            config.congestion_controller_factory(factory);
            return (config, Some(handle));
        }
        if let Some(inner) = inner {
            config.congestion_controller_factory(inner);
        }
        (config, None)
    }

    /// The rate Brutal should send at once the peer has answered, or 0 for
    /// "do not switch". `peer_receive` is the rate the peer said it can take
    /// (`None` for "auto"/unknown).
    pub fn brutal_rate(&self, peer_receive: Option<u64>) -> u64 {
        let up = self.params.up_bytes_per_sec;
        match self.params.congestion {
            Congestion::ForceBrutal => up,
            Congestion::Brutal => match peer_receive {
                Some(peer) if peer > 0 && up > 0 => up.min(peer),
                _ => 0,
            },
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(congestion: Congestion, up: u64) -> QuicShape {
        QuicShape {
            params: QuicParams {
                congestion,
                up_bytes_per_sec: up,
                ..QuicParams::default()
            },
            ..QuicShape::default()
        }
    }

    #[test]
    fn an_empty_shape_asks_for_nothing() {
        assert!(QuicShape::default().is_plain());
        assert!(!shape(Congestion::Bbr, 0).is_plain());
    }

    #[test]
    fn brutal_sends_at_the_smaller_of_what_each_end_allows() {
        let brutal = shape(Congestion::Brutal, 1_000_000);
        assert_eq!(brutal.brutal_rate(Some(400_000)), 400_000);
        assert_eq!(brutal.brutal_rate(Some(9_000_000)), 1_000_000);
        // The peer did not name a rate (auto): the shape is not switched.
        assert_eq!(brutal.brutal_rate(None), 0);
        assert_eq!(brutal.brutal_rate(Some(0)), 0);
        // Forced ignores the peer; no rate of our own means nothing to force.
        assert_eq!(
            shape(Congestion::ForceBrutal, 700_000).brutal_rate(None),
            700_000
        );
        assert_eq!(shape(Congestion::Brutal, 0).brutal_rate(Some(5)), 0);
        assert_eq!(shape(Congestion::Bbr, 5).brutal_rate(Some(5)), 0);
    }

    #[test]
    fn only_a_brutal_shape_gets_a_rate_handle() {
        let (_, handle) = shape(Congestion::Brutal, 1).transport(Duration::from_secs(30), None);
        assert!(handle.is_some());
        let (_, handle) = shape(Congestion::Bbr, 1).transport(Duration::from_secs(30), None);
        assert!(handle.is_none());
    }

    #[test]
    fn the_key_changes_with_every_part_of_the_shape() {
        let plain = QuicShape::default().key_text();
        let obfuscated = QuicShape {
            salamander: Some(Salamander::new("password-one").unwrap()),
            ..QuicShape::default()
        };
        let other = QuicShape {
            salamander: Some(Salamander::new("password-two").unwrap()),
            ..QuicShape::default()
        };
        assert_ne!(plain, obfuscated.key_text());
        assert_ne!(obfuscated.key_text(), other.key_text());
        assert_eq!(obfuscated.key_text(), obfuscated.clone().key_text());
        assert!(!obfuscated.key_text().contains("password"));
    }
}
