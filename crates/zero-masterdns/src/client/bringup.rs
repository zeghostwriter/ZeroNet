//! Getting from a list of resolvers to a live session.
//!
//! How it works: every resolver is probed in parallel for the largest query it
//! passes up and the largest answer it passes down (the same binary search the
//! upstream client runs, [`crate::mtu::binary_search_mtu`]); the ones that
//! answer are the usable set, and the tunnel runs at the smallest MTU of that
//! set so any of them can carry any packet. Then the session handshake runs
//! against one usable resolver after another until the server accepts.
//!
//! The probe is blocking socket code on purpose: the search is a plain
//! synchronous function (it is shared with its tests), so each resolver gets its
//! own blocking task rather than the search being rewritten as async.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::*;
use zero_protocol::masterdns::packet::BuildOptions;

use super::core::Tuning;
use super::wire::Wire;
use super::{Config, Error};
use crate::arq::close::CloseConfig;
use crate::arq::control::ControlConfig;
use crate::arq::data::Config as DataConfig;
use crate::carrier::{exchange, is_dns_response, Exchange, TunnelSocket};
use crate::mtu::*;
use crate::ping::PingConfig;
use crate::session::{
    SessionAcceptClientSettings, SessionConfig, SessionHandshake, SessionReplyOutcome,
};

/// How long the other resolvers get to pass their probes once one has.
const PROBE_GRACE: Duration = Duration::from_millis(1500);

/// Everything the runtime needs once the session is up.
pub(crate) struct Bringup {
    pub session_id: u8,
    pub cookie: u8,
    pub tuning: Tuning,
    pub resolvers: Vec<SocketAddr>,
    pub wire: Arc<Wire>,
}

/// A socket the host may exempt from the tunnel it is serving (see
/// `zero_core::platform`), as a plain blocking socket.
fn protected_socket() -> std::io::Result<UdpSocket> {
    zero_core::bind_protected_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

/// Send `question` to `resolver` and wait for the first DNS answer, or give up.
fn blocking_exchange(
    socket: &UdpSocket,
    question: &[u8],
    resolver: SocketAddr,
    timeout: Duration,
) -> Option<Vec<u8>> {
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.send_to(question, resolver).ok()?;
    let deadline = Instant::now() + timeout;
    let mut buffer = vec![0u8; 65535];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        socket
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let (n, _) = socket.recv_from(&mut buffer).ok()?;
        if is_dns_response(&buffer[..n]) {
            buffer.truncate(n);
            return Some(buffer);
        }
    }
}

fn probe_options(packet_type: u8, payload: &[u8]) -> BuildOptions<'_> {
    BuildOptions {
        session_id: PROBE_SENTINEL_SESSION_ID,
        packet_type,
        stream_id: PROBE_STREAM_ID,
        sequence_num: PROBE_SEQUENCE_NUM,
        fragment_id: PROBE_FRAGMENT_ID,
        total_fragments: PROBE_TOTAL_FRAGMENTS,
        payload,
        ..BuildOptions::default()
    }
}

/// The largest query and answer `resolver` passes, or `None` when it does not
/// answer a minimal probe at all.
fn probe_resolver(
    wire: &Wire,
    cfg: &Config,
    resolver: SocketAddr,
    upload_cap: i32,
) -> Option<(i32, i32)> {
    let socket = protected_socket().ok()?;
    let timeout = cfg.probe_timeout;
    let up = binary_search_mtu(
        cfg.min_upload_mtu,
        upload_cap,
        upload_accept_floor(cfg.min_upload_mtu),
        cfg.probe_retries,
        |candidate, _| {
            let code: u32 = rand::random();
            let Some(payload) = build_upload_probe_payload(candidate, cfg.base64_replies, code)
            else {
                return ProbeOutcome::Fail;
            };
            let Ok(question) = wire.question(&probe_options(PACKET_MTU_UP_REQ, &payload)) else {
                return ProbeOutcome::Fail;
            };
            let started = Instant::now();
            let Some(answer) = blocking_exchange(&socket, &question, resolver, timeout) else {
                return ProbeOutcome::Fail;
            };
            let ok = wire
                .replies(&answer)
                .iter()
                .any(|r| validate_upload_response(r.packet_type, &r.payload, code, candidate));
            if ok {
                ProbeOutcome::Pass(started.elapsed())
            } else {
                ProbeOutcome::Fail
            }
        },
    )?
    .0;
    let down = binary_search_mtu(
        cfg.min_download_mtu,
        cfg.max_download_mtu,
        download_accept_floor(cfg.min_download_mtu),
        cfg.probe_retries,
        |candidate, _| {
            let code: u32 = rand::random();
            let Some(probe) = build_download_probe_payload(candidate, up, cfg.base64_replies, code)
            else {
                return ProbeOutcome::Fail;
            };
            let Ok(question) = wire.question(&probe_options(PACKET_MTU_DOWN_REQ, &probe.payload))
            else {
                return ProbeOutcome::Fail;
            };
            let started = Instant::now();
            let Some(answer) = blocking_exchange(&socket, &question, resolver, timeout) else {
                return ProbeOutcome::Fail;
            };
            let ok = wire.replies(&answer).iter().any(|r| {
                validate_download_response(r.packet_type, &r.payload, code, probe.effective_size)
            });
            if ok {
                ProbeOutcome::Pass(started.elapsed())
            } else {
                ProbeOutcome::Fail
            }
        },
    )?
    .0;
    Some((up, down))
}

/// The settings the client asks for; the server's policy block may tighten them.
fn requested(cfg: &Config) -> SessionAcceptClientSettings {
    SessionAcceptClientSettings {
        packet_duplication_count: 1,
        setup_packet_duplication_count: 1,
        max_upload_mtu: i64::from(cfg.max_upload_mtu),
        max_download_mtu: i64::from(cfg.max_download_mtu),
        rx_tx_workers: cfg.workers as i64,
        ping_aggressive_interval: 0.1,
        max_packets_per_batch: 8,
        arq_window_size: 600,
        arq_data_nack_max_gap: 16,
        compression_min_size: 120,
        arq_initial_rto_seconds: 1.0,
        arq_control_initial_rto_seconds: 0.5,
        arq_max_rto_seconds: 5.0,
        arq_control_max_rto_seconds: 3.0,
    }
}

/// Probe the resolvers, then run the handshake. See the module text.
pub(crate) async fn bring_up(cfg: &Config) -> Result<Bringup, Error> {
    if cfg.resolvers.is_empty() {
        return Err(Error::NoResolver);
    }
    let wire = Arc::new(Wire::new(
        &cfg.domain,
        &cfg.key,
        cfg.method,
        cfg.base64_replies,
    )?);
    let upload_cap =
        upload_max_limit(cfg.max_upload_mtu).min(wire.max_payload(PACKET_MTU_UP_REQ) as i32);
    if upload_cap < upload_accept_floor(cfg.min_upload_mtu) {
        return Err(Error::Config(
            "the tunnel domain is too long: no query would fit".into(),
        ));
    }

    // Probe every resolver at once; each blocks a thread for its search.
    let cfg_shared = Arc::new(cfg.clone());
    let mut tasks = tokio::task::JoinSet::new();
    for (index, &resolver) in cfg.resolvers.iter().enumerate() {
        let (wire, cfg) = (wire.clone(), cfg_shared.clone());
        tasks.spawn_blocking(move || (index, probe_resolver(&wire, &cfg, resolver, upload_cap)));
    }
    // Do not wait for the slowest: a dead resolver takes its full timeout to
    // give up, which would delay every connect. Once one resolver has passed,
    // the others get a short grace period and whoever answered by then is used.
    let mut usable: Vec<(usize, i32, i32)> = Vec::new();
    let mut grace_until: Option<tokio::time::Instant> = None;
    loop {
        let next = match grace_until {
            Some(until) => match tokio::time::timeout_at(until, tasks.join_next()).await {
                Ok(done) => done,
                Err(_) => break,
            },
            None => tasks.join_next().await,
        };
        let Some(done) = next else { break };
        if let Ok((index, Some((up, down)))) = done {
            usable.push((index, up, down));
            grace_until.get_or_insert(tokio::time::Instant::now() + PROBE_GRACE);
        }
    }
    tasks.detach_all();
    if usable.is_empty() {
        return Err(Error::NoResolver);
    }
    usable.sort_unstable();
    let resolvers: Vec<SocketAddr> = usable.iter().map(|(i, _, _)| cfg.resolvers[*i]).collect();
    let upload_mtu = usable
        .iter()
        .map(|(_, up, _)| *up)
        .min()
        .expect("not empty");
    let download_mtu = usable
        .iter()
        .map(|(_, _, down)| *down)
        .min()
        .expect("not empty");

    let socket = {
        let std = protected_socket()?;
        std.set_nonblocking(true)?;
        TunnelSocket::from_socket(tokio::net::UdpSocket::from_std(std)?)
    };
    let mut handshake = SessionHandshake::new(SessionConfig {
        base64_reply: cfg.base64_replies,
        upload_mtu: upload_mtu as u16,
        download_mtu: download_mtu as u16,
        ..SessionConfig::client_defaults()
    });
    let active = vec![true; resolvers.len()];
    let mut buffer = vec![0u8; 65535];
    let mut accepted = None;
    for _ in 0..cfg.session_attempts {
        let attempt = handshake
            .begin_attempt(&active, rand::random())
            .map_err(|_| Error::NoResolver)?;
        let question = wire.question(&BuildOptions {
            packet_type: attempt.packet_type,
            payload: &attempt.payload,
            ..BuildOptions::default()
        })?;
        let resolver = resolvers[attempt.resolver_index];
        // Three copies, a little apart, like the upstream client: one lost
        // datagram should not cost a whole retry.
        let mut outcome = SessionReplyOutcome::Ignored;
        for copy in 0..3 {
            if copy > 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if let Ok(Exchange::Response { len, .. }) =
                exchange(&socket, &question, resolver, cfg.probe_timeout, &mut buffer).await
            {
                for reply in wire.replies(&buffer[..len]) {
                    outcome = handshake.apply_reply(
                        reply.packet_type,
                        &reply.payload,
                        requested(cfg),
                        Instant::now(),
                    );
                    if !matches!(outcome, SessionReplyOutcome::Ignored) {
                        break;
                    }
                }
                if !matches!(outcome, SessionReplyOutcome::Ignored) {
                    break;
                }
            }
        }
        match outcome {
            SessionReplyOutcome::Accepted {
                session_id,
                session_cookie,
                response_mode,
                applied_settings,
                ..
            } => {
                accepted = Some((session_id, session_cookie, response_mode, applied_settings));
                break;
            }
            SessionReplyOutcome::Busy { .. } => return Err(Error::Busy),
            SessionReplyOutcome::Ignored => {
                tokio::time::sleep(handshake.note_attempt_failed().min(Duration::from_secs(3)))
                    .await;
            }
        }
    }
    let (session_id, cookie, response_mode, applied) = accepted.ok_or(Error::NoSession)?;

    // The answers come back in the mode the server agreed to.
    wire.set_base64(response_mode == MTU_PROBE_BASE64_REPLY);

    let settings = applied.unwrap_or_else(|| requested(cfg));
    let max_upload = settings.max_upload_mtu.max(1) as usize;
    let chunk = (upload_mtu as usize)
        .min(max_upload)
        .min(wire.max_payload(PACKET_STREAM_DATA))
        .max(1);
    let seconds = |v: f64| Duration::from_secs_f64(v.clamp(0.05, 3600.0));
    let data = DataConfig {
        window_size: settings.arq_window_size.max(1) as usize,
        initial_rto: seconds(settings.arq_initial_rto_seconds),
        max_rto: seconds(settings.arq_max_rto_seconds),
        data_nack_max_gap: settings.arq_data_nack_max_gap.max(0) as usize,
        ..DataConfig::client_defaults()
    };
    let control = ControlConfig {
        control_rto: seconds(settings.arq_control_initial_rto_seconds),
        control_max_rto: seconds(settings.arq_control_max_rto_seconds),
        ..ControlConfig::client_defaults()
    };
    let ping = PingConfig {
        aggressive_interval: seconds(settings.ping_aggressive_interval)
            .max(Duration::from_millis(50)),
        ..PingConfig::default()
    };
    Ok(Bringup {
        session_id,
        cookie,
        tuning: Tuning {
            chunk,
            data,
            control,
            close: CloseConfig::client_defaults(),
            ping,
        },
        resolvers,
        wire,
    })
}
