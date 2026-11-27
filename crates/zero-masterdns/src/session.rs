//! The session handshake, as a pure (sans-IO) state machine.
//!
//! Before a single stream can be opened, the client must agree a *session* with
//! the server: a one-byte session id, a one-byte cookie, the compression codecs
//! for each direction, the reply mode (raw or base64 TXT), and an optional
//! block of server-imposed limits. This module is the referee for that
//! agreement. It is deliberately socket-free and clock-explicit: it builds the
//! `SESSION_INIT` payload, picks which resolver to try next, reads the server's
//! `SESSION_ACCEPT` / `SESSION_BUSY` reply, and hands back the backoff delay to
//! wait before the next try. The actual DNS send, the three-way racing, and the
//! timers all live in a thin async wrapper on top.
//!
//! # The anti-spoofing verify code
//!
//! Every attempt carries four random bytes the client picks (the *verify
//! code*). A real `SESSION_ACCEPT` echoes them in its verify field; a real
//! `SESSION_BUSY` carries them as its first four payload bytes. Any reply whose
//! code does not match is treated as noise and ignored, so a blind forged
//! answer cannot push the client into a bogus session. The caller supplies the
//! random bytes (this module stays deterministic for testing); it caches them
//! across the racing copies of one attempt so every racer carries the same
//! code, exactly as the Go client does.
//!
//! # What an attempt looks like
//!
//! 1. [`SessionHandshake::begin_attempt`] builds (and caches) the init payload
//!    and round-robins to the next usable resolver, returning the index to send
//!    to and the bytes to send. The caller fires `racing_count` copies of that
//!    one query at the chosen resolver, staggered by `stagger`.
//! 2. Each reply is fed to [`SessionHandshake::apply_reply`], which returns
//!    [`SessionReplyOutcome`]: `Accepted` (session is live — stop the race),
//!    `Busy` (server is full — stop and wait out the cooldown), or `Ignored`
//!    (not a valid reply — keep waiting on the other racers).
//! 3. On a failed attempt the caller calls [`SessionHandshake::note_attempt_failed`]
//!    for the backoff delay before trying again; on success it calls
//!    [`SessionHandshake::note_session_established`] to reset the backoff.
//!
//! Ported from the Go client's `internal/client/session.go` and
//! `internal/vpnproto/session_accept.go` at the pinned release
//! `v2026.06.13.234407-7de2476`.

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use zero_protocol::masterdns::compression::{
    normalize_available_type, split_pair, DEFAULT_MIN_SIZE, TYPE_OFF,
};
use zero_protocol::masterdns::enums::{
    PACKET_SESSION_ACCEPT, PACKET_SESSION_BUSY, PACKET_SESSION_INIT,
};
use zero_protocol::masterdns::packet::decode_session_accept_payload;
use zero_protocol::masterdns::session::{build_session_init_payload, VERIFY_CODE_LEN};
use zero_protocol::masterdns::SessionAcceptClientPolicy;

/// How many bytes of a `SESSION_BUSY` payload must equal the verify code.
const SESSION_BUSY_PAYLOAD_SIZE: usize = VERIFY_CODE_LEN;

/// The client's own tunable knobs for the handshake. Compression ids and MTUs
/// are what goes *into* the init payload; the rest govern the retry schedule
/// and the busy cooldown. Build one with [`SessionConfig::client_defaults`] and
/// adjust, or with [`SessionConfig::new`] to get the same flooring the Go
/// config layer applies.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionConfig {
    /// Ask the server to answer in base64 TXT text rather than raw bytes.
    pub base64_reply: bool,
    /// Requested upload codec id (see [`zero_protocol::masterdns::compression`]).
    pub upload_compression: u8,
    /// Requested download codec id.
    pub download_compression: u8,
    /// Probed upload MTU, carried big-endian in the init payload.
    pub upload_mtu: u16,
    /// Probed download MTU, carried big-endian in the init payload.
    pub download_mtu: u16,
    /// How long a `SESSION_BUSY` reply parks the client before it may retry.
    pub busy_retry_interval: Duration,
    /// The first retry delay after a failed attempt.
    pub retry_base: Duration,
    /// Added once per failure beyond `retry_linear_after`.
    pub retry_step: Duration,
    /// Failures up to this count all wait `retry_base`; past it the delay grows.
    pub retry_linear_after: u32,
    /// The retry delay never exceeds this.
    pub retry_max: Duration,
}

impl SessionConfig {
    /// The Go client's shipped defaults: 1 s base, 1 s step, linear for the
    /// first five failures then growing to a 60 s cap, 60 s busy cooldown.
    pub fn client_defaults() -> Self {
        Self {
            base64_reply: false,
            upload_compression: TYPE_OFF,
            download_compression: TYPE_OFF,
            upload_mtu: 0,
            download_mtu: 0,
            busy_retry_interval: Duration::from_secs(60),
            retry_base: Duration::from_secs(1),
            retry_step: Duration::from_secs(1),
            retry_linear_after: 5,
            retry_max: Duration::from_secs(60),
        }
    }

    /// Apply the same clamps the Go config layer enforces so a hand-built
    /// config can never produce a nonsensical schedule: base in `0.1..=60` s,
    /// step in `0..=60` s, linear-after in `0..=1000`, max in
    /// `base..=3600` s, busy cooldown in `1..=3600` s.
    pub fn new(mut cfg: SessionConfig) -> Self {
        cfg.retry_base = clamp_duration(
            cfg.retry_base,
            Duration::from_millis(100),
            Duration::from_secs(60),
        );
        cfg.retry_step = clamp_duration(cfg.retry_step, Duration::ZERO, Duration::from_secs(60));
        cfg.retry_linear_after = cfg.retry_linear_after.min(1000);
        cfg.retry_max = clamp_duration(cfg.retry_max, cfg.retry_base, Duration::from_secs(3600));
        cfg.busy_retry_interval = clamp_duration(
            cfg.busy_retry_interval,
            Duration::from_secs(1),
            Duration::from_secs(3600),
        );
        cfg
    }
}

/// The outcome of feeding one reply packet to the handshake.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionReplyOutcome {
    /// A valid `SESSION_ACCEPT`: the session is now live. The caller should stop
    /// the racing copies and bring the runtime up. If the reply carried the
    /// optional policy block, `applied_settings` holds the client settings
    /// after the server's limits were applied, for the caller to adopt.
    Accepted {
        session_id: u8,
        session_cookie: u8,
        response_mode: u8,
        upload_compression: u8,
        download_compression: u8,
        applied_settings: Option<SessionAcceptClientSettings>,
    },
    /// A valid `SESSION_BUSY`: the server is at capacity. The caller should stop
    /// the race and wait until `retry_at` before trying again.
    Busy { retry_at: Instant },
    /// The reply was not usable (wrong type, bad verify code, malformed, or the
    /// session was already live). No state changed; keep waiting on the race.
    Ignored,
}

/// Why an attempt could not even be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// No resolver in the active set is usable right now.
    NoValidConnections,
}

/// What one attempt should put on the wire: the resolver to send to and the
/// `SESSION_INIT` query payload. The caller fires `racing_count` staggered
/// copies of this at the chosen resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttempt {
    /// Index into the active-resolver slice the caller passed to
    /// [`SessionHandshake::begin_attempt`].
    pub resolver_index: usize,
    /// Always [`PACKET_SESSION_INIT`]; carried so the caller can build the query
    /// without re-deriving it.
    pub packet_type: u8,
    /// The ten-byte init payload (cached across the racing copies).
    pub payload: [u8; 10],
}

/// The client's live settings the server's policy block may tighten. These are
/// the knobs a `SESSION_ACCEPT` policy can clamp; the two `*_max_rto_seconds`
/// fields are read-only ceilings used when clamping the initial RTOs, never
/// themselves changed. Mirrors the Go `SessionAcceptClientSettings`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionAcceptClientSettings {
    pub packet_duplication_count: i64,
    pub setup_packet_duplication_count: i64,
    pub max_upload_mtu: i64,
    pub max_download_mtu: i64,
    pub rx_tx_workers: i64,
    pub ping_aggressive_interval: f64,
    pub max_packets_per_batch: i64,
    pub arq_window_size: i64,
    pub arq_data_nack_max_gap: i64,
    pub compression_min_size: i64,
    pub arq_initial_rto_seconds: f64,
    pub arq_control_initial_rto_seconds: f64,
    pub arq_max_rto_seconds: f64,
    pub arq_control_max_rto_seconds: f64,
}

/// Clamp a client's requested settings down to what the server's policy block
/// allows. This is a pure transform: it reads `current` and the server
/// `policy`, and returns the effective settings. Each `max_*` in the policy is
/// a ceiling (floored at 1 so a zero never pins a value to 0); the two
/// interval/size minimums raise the client's value if it was lower. The two
/// RTO fields are clamped between the policy minimum and the client's own
/// matching max-RTO ceiling.
///
/// Mirrors the Go `ApplySessionAcceptClientPolicy` exactly, including the way
/// `setup_packet_duplication_count` is clamped into
/// `[packet_duplication_count, max(policy_max, packet_duplication_count)]`
/// *after* `packet_duplication_count` is itself clamped.
pub fn apply_session_accept_client_policy(
    mut current: SessionAcceptClientSettings,
    policy: &SessionAcceptClientPolicy,
) -> SessionAcceptClientSettings {
    current.packet_duplication_count = current
        .packet_duplication_count
        .clamp(1, policy.max_packet_duplication_count.max(1));
    current.setup_packet_duplication_count = current.setup_packet_duplication_count.clamp(
        current.packet_duplication_count,
        policy
            .max_setup_duplication_count
            .max(current.packet_duplication_count),
    );
    current.max_upload_mtu = current
        .max_upload_mtu
        .clamp(1, policy.max_upload_mtu.max(1));
    current.max_download_mtu = current
        .max_download_mtu
        .clamp(1, policy.max_download_mtu.max(1));
    current.rx_tx_workers = current
        .rx_tx_workers
        .clamp(1, policy.max_rx_tx_workers.max(1));
    current.ping_aggressive_interval = clamp_f64(
        current.ping_aggressive_interval,
        policy.min_ping_aggressive_interval,
        30.0,
    );
    current.max_packets_per_batch = current
        .max_packets_per_batch
        .clamp(1, policy.max_packets_per_batch.max(1));
    current.arq_window_size = current
        .arq_window_size
        .clamp(1, policy.max_arq_window_size.max(1));
    current.arq_data_nack_max_gap = current
        .arq_data_nack_max_gap
        .clamp(0, policy.max_arq_data_nack_max_gap.max(0));
    current.compression_min_size = current
        .compression_min_size
        .max(policy.min_compression_min_size.max(1));
    current.arq_initial_rto_seconds = clamp_f64(
        current.arq_initial_rto_seconds,
        policy.min_arq_initial_rto_seconds,
        current.arq_max_rto_seconds,
    );
    current.arq_control_initial_rto_seconds = clamp_f64(
        current.arq_control_initial_rto_seconds,
        policy.min_arq_initial_rto_seconds,
        current.arq_control_max_rto_seconds,
    );
    current
}

/// The handshake state machine for one client. It carries the retry/backoff
/// bookkeeping, the cached init payload for the current attempt, the busy
/// cooldown, and — once a `SESSION_ACCEPT` lands — the agreed session id,
/// cookie, reply mode and compression codecs.
///
/// Invariants:
///  * The cached init payload (`init_payload`) and its verify code are built
///    once per attempt and reused by every racing copy, so all racers carry the
///    same verify code. [`SessionHandshake::reset_init_state`] clears the cache
///    so the next attempt picks a fresh code; it runs automatically on a
///    successful accept.
///  * `cursor` always indexes the *active* resolver slice last passed in, taken
///    modulo its length, so round-robin survives the set changing size between
///    attempts (it just wraps against the new length).
///  * Once `ready` is set, `apply_reply` ignores further replies: the session
///    is established and a late racer's answer cannot disturb it.
#[derive(Debug, Clone)]
pub struct SessionHandshake {
    cfg: SessionConfig,
    /// Round-robin cursor over the active resolver set.
    cursor: usize,
    /// Consecutive failed attempts, driving the backoff. Reset on success.
    failures: u32,
    /// The cached init payload + verify code for the in-flight attempt, if any.
    init_payload: Option<[u8; 10]>,
    verify_code: [u8; VERIFY_CODE_LEN],
    /// When set, the client is parked after a `SESSION_BUSY` until this instant.
    busy_until: Option<Instant>,
    /// Whether a session is live. Once true, replies are ignored.
    ready: bool,
    session_id: u8,
    session_cookie: u8,
    response_mode: u8,
    upload_compression: u8,
    download_compression: u8,
}

impl SessionHandshake {
    /// Start a handshake with the given config. The config is passed through
    /// [`SessionConfig::new`] so its schedule is always sane.
    pub fn new(cfg: SessionConfig) -> Self {
        Self {
            cfg: SessionConfig::new(cfg),
            cursor: 0,
            failures: 0,
            init_payload: None,
            verify_code: [0u8; VERIFY_CODE_LEN],
            busy_until: None,
            ready: false,
            session_id: 0,
            session_cookie: 0,
            response_mode: 0,
            upload_compression: TYPE_OFF,
            download_compression: TYPE_OFF,
        }
    }

    /// Begin the next attempt: build (or reuse) the init payload and round-robin
    /// to the next usable resolver.
    ///
    /// `active` is the current active-resolver set; each `true` marks a resolver
    /// that is valid and has a non-empty key (the caller folds Go's
    /// `conn.IsValid && conn.Key != ""` into one bool). `verify` is the four
    /// random bytes for this attempt — it is only read when a new payload is
    /// built, so passing a fresh code on every call is fine; a cached attempt
    /// keeps the code it was built with.
    ///
    /// Returns the resolver index to send to and the bytes to send, or
    /// [`SessionError::NoValidConnections`] when nothing in `active` is usable.
    pub fn begin_attempt(
        &mut self,
        active: &[bool],
        verify: [u8; VERIFY_CODE_LEN],
    ) -> Result<SessionAttempt, SessionError> {
        if self.init_payload.is_none() {
            self.verify_code = verify;
            self.init_payload = Some(build_session_init_payload(
                self.cfg.base64_reply,
                self.cfg.upload_compression,
                self.cfg.download_compression,
                self.cfg.upload_mtu,
                self.cfg.download_mtu,
                self.verify_code,
            ));
            self.cursor = 0;
        }

        let resolver_index = self.next_resolver(active)?;
        Ok(SessionAttempt {
            resolver_index,
            packet_type: PACKET_SESSION_INIT,
            payload: self.init_payload.expect("payload built above"),
        })
    }

    /// Round-robin to the next usable resolver, advancing the cursor past it.
    /// Scans at most one full lap from the cursor; returns the first usable
    /// index or `NoValidConnections` if the lap finds none.
    fn next_resolver(&mut self, active: &[bool]) -> Result<usize, SessionError> {
        let len = active.len();
        if len == 0 {
            return Err(SessionError::NoValidConnections);
        }
        let start = self.cursor % len;
        for checked in 0..len {
            let idx = (start + checked) % len;
            if !active[idx] {
                continue;
            }
            self.cursor = (idx + 1) % len;
            return Ok(idx);
        }
        Err(SessionError::NoValidConnections)
    }

    /// Feed one reply packet to the handshake. `current` is the client's live
    /// settings, used only to clamp against an accept's optional policy block.
    /// `now` stamps the busy cooldown. See [`SessionReplyOutcome`].
    pub fn apply_reply(
        &mut self,
        packet_type: u8,
        payload: &[u8],
        current: SessionAcceptClientSettings,
        now: Instant,
    ) -> SessionReplyOutcome {
        if self.ready {
            return SessionReplyOutcome::Ignored;
        }

        match packet_type {
            PACKET_SESSION_BUSY => {
                if payload.len() < SESSION_BUSY_PAYLOAD_SIZE
                    || payload[..SESSION_BUSY_PAYLOAD_SIZE] != self.verify_code[..]
                {
                    return SessionReplyOutcome::Ignored;
                }
                let retry_at = now + self.cfg.busy_retry_interval;
                self.busy_until = Some(retry_at);
                SessionReplyOutcome::Busy { retry_at }
            }
            PACKET_SESSION_ACCEPT => {
                let accept = match decode_session_accept_payload(payload) {
                    Ok(a) => a,
                    Err(_) => return SessionReplyOutcome::Ignored,
                };
                if accept.verify_code != self.verify_code {
                    return SessionReplyOutcome::Ignored;
                }

                let response_mode = self.init_payload.map_or(0, |p| p[0]);
                let (upload, download) = split_pair(accept.compression_pair);
                let applied_settings = accept
                    .client_policy
                    .map(|policy| apply_session_accept_client_policy(current, &policy));

                self.session_id = accept.session_id;
                self.session_cookie = accept.session_cookie;
                self.response_mode = response_mode;
                self.upload_compression = upload;
                self.download_compression = download;
                self.ready = true;
                self.busy_until = None;
                self.reset_init_state();

                SessionReplyOutcome::Accepted {
                    session_id: accept.session_id,
                    session_cookie: accept.session_cookie,
                    response_mode,
                    upload_compression: upload,
                    download_compression: download,
                    applied_settings,
                }
            }
            _ => SessionReplyOutcome::Ignored,
        }
    }

    /// Record that an attempt failed and return the delay to wait before the
    /// next one. Increments the failure counter first, so the first failure
    /// yields `retry_base`.
    pub fn note_attempt_failed(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.retry_delay(self.failures)
    }

    /// Reset the backoff after a session comes up (or the caller otherwise wants
    /// a clean slate for the next cold start).
    pub fn note_session_established(&mut self) {
        self.failures = 0;
    }

    /// Tear the live session down (a reset was requested): clear `ready` and the
    /// agreed fields and drop any cached init payload, so the next
    /// `begin_attempt` builds a fresh one. The backoff is left to the caller via
    /// [`SessionHandshake::note_attempt_failed`], matching the Go reset path.
    pub fn reset_session(&mut self) {
        self.ready = false;
        self.session_id = 0;
        self.session_cookie = 0;
        self.response_mode = 0;
        self.upload_compression = TYPE_OFF;
        self.download_compression = TYPE_OFF;
        self.reset_init_state();
    }

    /// Drop the cached init payload and verify code so the next attempt starts
    /// fresh. Does not touch the backoff or the live-session fields.
    pub fn reset_init_state(&mut self) {
        self.init_payload = None;
        self.verify_code = [0u8; VERIFY_CODE_LEN];
        self.cursor = 0;
    }

    /// The backoff delay for a given failure count, mirroring the Go
    /// `nextSessionInitRetryDelay`: zero for no failures, `retry_base` through
    /// the first `retry_linear_after` failures, then `+retry_step` per extra
    /// failure, capped at `retry_max`.
    pub fn retry_delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let mut delay = self.cfg.retry_base;
        if failures > self.cfg.retry_linear_after {
            let extra = failures - self.cfg.retry_linear_after;
            delay += self.cfg.retry_step * extra;
        }
        delay.min(self.cfg.retry_max)
    }

    /// Whether the client is parked in a busy cooldown at `now`.
    pub fn is_busy(&self, now: Instant) -> bool {
        self.busy_until.is_some_and(|t| now < t)
    }

    /// The instant the busy cooldown ends, if one is armed.
    pub fn busy_until(&self) -> Option<Instant> {
        self.busy_until
    }

    /// Whether a session is live.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// The agreed session id (0 until an accept lands).
    pub fn session_id(&self) -> u8 {
        self.session_id
    }

    /// The agreed session cookie.
    pub fn session_cookie(&self) -> u8 {
        self.session_cookie
    }

    /// The reply mode the server will use (echoed from the init payload's first
    /// byte on accept).
    pub fn response_mode(&self) -> u8 {
        self.response_mode
    }

    /// The agreed upload codec id.
    pub fn upload_compression(&self) -> u8 {
        self.upload_compression
    }

    /// The agreed download codec id.
    pub fn download_compression(&self) -> u8 {
        self.download_compression
    }

    /// The current failure count driving the backoff.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

/// Clamp a `Duration` into `[lo, hi]`. (`Duration` is `Ord`, but spelling it out
/// keeps the intent obvious next to the `f64` clamp.)
fn clamp_duration(v: Duration, lo: Duration, hi: Duration) -> Duration {
    v.clamp(lo, hi)
}

/// Clamp an `f64` into `[lo, hi]` the Go way (plain comparisons, no NaN games),
/// so the scaled interval/RTO values match `clampFloat64` byte-for-byte.
fn clamp_f64(v: f64, lo: f64, hi: f64) -> f64 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Compute the effective upload/download compression after a session's MTUs are
/// known, mirroring the Go `applySessionCompressionPolicy`: a codec is forced
/// off when its direction's MTU is below the 100-byte warning threshold, and
/// also when the MTU is at or below `compression_min_size`. An MTU of zero
/// (unknown) leaves the codec alone. Unknown codec ids fold to
/// [`TYPE_OFF`] first.
///
/// Returns the `(upload, download)` codec ids the session should actually use.
pub fn effective_session_compression(
    upload_compression: u8,
    download_compression: u8,
    upload_mtu: i64,
    download_mtu: i64,
    compression_min_size: i64,
) -> (u8, u8) {
    const MTU_WARNING_THRESHOLD: i64 = 100;
    let min_size = if compression_min_size <= 0 {
        DEFAULT_MIN_SIZE as i64
    } else {
        compression_min_size
    };

    let mut upload = normalize_available_type(upload_compression);
    let mut download = normalize_available_type(download_compression);

    if upload_mtu > 0 && (upload_mtu < MTU_WARNING_THRESHOLD || upload_mtu <= min_size) {
        upload = TYPE_OFF;
    }
    if download_mtu > 0 && (download_mtu < MTU_WARNING_THRESHOLD || download_mtu <= min_size) {
        download = TYPE_OFF;
    }

    (upload, download)
}
