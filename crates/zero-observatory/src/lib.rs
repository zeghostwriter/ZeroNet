//! Local network observation and evidence-driven connection planning.
//!
//! The profile deliberately stores capability evidence, never destinations.
//! It is keyed by a one-way local identity supplied by the platform adapter
//! (gateway/interface/SSID material), so a planner can adapt without becoming
//! a telemetry or browsing-history subsystem.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zero_core::{Failure, FailureKind, Stage};

const HISTORY_LIMIT: usize = 64;

/// Bounded per-outbound health evidence used by balancer selection. This is
/// deliberately separate from `NetworkProfile`: endpoint tags are local
/// configuration labels and the table never stores destinations or payloads.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct OutboundHealth {
    pub successes: u32,
    pub failures: u32,
    pub consecutive_failures: u32,
    pub latency: Option<Duration>,
    pub last_success: Option<Duration>,
}

#[derive(Debug, Default)]
pub struct HealthTable {
    samples: HashMap<Arc<str>, OutboundHealth>,
}

impl HealthTable {
    /// The sample for `tag`, allocating the key only the first time a tag is
    /// seen — this runs once per proxied session.
    fn sample_mut(&mut self, tag: &str) -> &mut OutboundHealth {
        if !self.samples.contains_key(tag) {
            self.samples
                .insert(Arc::from(tag), OutboundHealth::default());
        }
        self.samples
            .get_mut(tag)
            .expect("the sample was inserted above")
    }

    pub fn record_success(&mut self, tag: &str, elapsed: Duration) {
        let sample = self.sample_mut(tag);
        sample.successes = sample.successes.saturating_add(1);
        sample.consecutive_failures = 0;
        sample.last_success = Some(elapsed);
        sample.latency = Some(match sample.latency {
            Some(previous) => {
                let previous = previous.as_secs_f64();
                let current = elapsed.as_secs_f64();
                // `try_from`: an absurd elapsed value must not panic the
                // runtime through `Duration::from_secs_f64`'s overflow check.
                Duration::try_from_secs_f64(previous.mul_add(0.8, current * 0.2)).unwrap_or(elapsed)
            }
            None => elapsed,
        });
    }

    pub fn record_failure(&mut self, tag: &str) {
        let sample = self.sample_mut(tag);
        sample.failures = sample.failures.saturating_add(1);
        sample.consecutive_failures = sample.consecutive_failures.saturating_add(1);
    }

    pub fn sample(&self, tag: &str) -> OutboundHealth {
        self.samples.get(tag).copied().unwrap_or_default()
    }

    /// Select the healthiest member. Unknown members retain a neutral prior,
    /// so a fresh configuration still probes every server instead of pinning
    /// to the first entry.
    pub fn choose(
        &self,
        strategy: BalancerHealthStrategy,
        tags: &[Arc<str>],
        ticket: u64,
    ) -> usize {
        debug_assert!(!tags.is_empty());
        let mut best = 0usize;
        let mut best_score = f64::INFINITY;
        for (index, tag) in tags.iter().enumerate() {
            let sample = self.sample(tag);
            let score = match strategy {
                BalancerHealthStrategy::LeastPing => {
                    sample
                        .latency
                        .map(|duration| duration.as_secs_f64())
                        .unwrap_or(5.0)
                        + sample.consecutive_failures as f64 * 2.0
                }
                BalancerHealthStrategy::LeastLoad => {
                    sample.consecutive_failures as f64 * 10.0
                        + sample.failures.saturating_sub(sample.successes) as f64
                }
            };
            if score < best_score
                || (score == best_score && (ticket as usize) % tags.len() == index)
            {
                best = index;
                best_score = score;
            }
        }
        best
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalancerHealthStrategy {
    LeastPing,
    LeastLoad,
}

/// The ordered Iran resilience ladder from PLAN-02 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathStrategy {
    DirectReality,
    FingerprintRotation,
    /// Idle probing plus proactive carrier rotation. Sits below
    /// fragmentation because it is cheaper — a few bytes a minute and no
    /// added latency — and because it answers a different question: a
    /// flow-timeout policy kills a connection the ClientHello already got
    /// past, which is precisely where splitting the hello cannot help
    /// (PLAN-01 §5.2).
    KeepaliveShaping,
    ClientHelloFragment,
    SniDesync,
    RealityXhttp,
    CdnWebSocket,
    CdnAlternatePort,
    CdnCleanIp,
    AmneziaWireguard,
}

/// Coarse access classes used for failover. A class transition means the
/// current endpoint family is unavailable, not merely that one handshake
/// failed, so the planner can preserve evidence while moving from a direct
/// VPS to a CDN or a UDP tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccessClass {
    DirectReality,
    CdnFronted,
    WarpTunnel,
}

impl AccessClass {
    pub const ALL: [Self; 3] = [Self::DirectReality, Self::CdnFronted, Self::WarpTunnel];

    /// The next class to try when this one is unreachable as a whole.
    pub fn next(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|candidate| *candidate == self)?;
        Self::ALL.get(index + 1).copied()
    }

    /// The cheapest rung inside this class. A class transition restarts at the
    /// bottom: the expensive disguises within the old class were answers to a
    /// different question, and carrying them over would pay their cost for no
    /// reason.
    pub fn first_strategy(self) -> PathStrategy {
        match self {
            Self::DirectReality => PathStrategy::DirectReality,
            Self::CdnFronted => PathStrategy::CdnWebSocket,
            Self::WarpTunnel => PathStrategy::AmneziaWireguard,
        }
    }
}

impl PathStrategy {
    pub const ALL: [Self; 10] = [
        Self::DirectReality,
        Self::FingerprintRotation,
        Self::KeepaliveShaping,
        Self::ClientHelloFragment,
        Self::SniDesync,
        Self::RealityXhttp,
        Self::CdnWebSocket,
        Self::CdnAlternatePort,
        Self::CdnCleanIp,
        Self::AmneziaWireguard,
    ];

    pub fn next(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|candidate| *candidate == self)?;
        Self::ALL.get(index + 1).copied()
    }

    pub fn previous(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|candidate| *candidate == self)?;
        index.checked_sub(1).and_then(|i| Self::ALL.get(i).copied())
    }

    pub fn access_class(self) -> AccessClass {
        match self {
            Self::DirectReality
            | Self::FingerprintRotation
            | Self::KeepaliveShaping
            | Self::ClientHelloFragment
            | Self::SniDesync
            | Self::RealityXhttp => AccessClass::DirectReality,
            Self::CdnWebSocket | Self::CdnAlternatePort | Self::CdnCleanIp => {
                AccessClass::CdnFronted
            }
            Self::AmneziaWireguard => AccessClass::WarpTunnel,
        }
    }

    /// Compact representation used by the runtime's lock-free hot path. The
    /// order is part of the ladder contract above; unknown values fall back
    /// to the least invasive strategy rather than enabling an unsafe rung.
    pub fn as_u8(self) -> u8 {
        Self::ALL
            .iter()
            .position(|candidate| *candidate == self)
            .unwrap_or(0) as u8
    }

    pub fn from_u8(value: u8) -> Self {
        Self::ALL
            .get(value as usize)
            .copied()
            .unwrap_or(Self::DirectReality)
    }
}

/// One probe result. It is safe to persist because it contains no host,
/// domain, URL, IP or user payload.
#[derive(Debug, Clone)]
pub struct Observation {
    pub strategy: PathStrategy,
    pub stage: Stage,
    pub failure: Option<FailureKind>,
    pub bytes_at_failure: u64,
    pub elapsed_at_failure: Duration,
    pub success: bool,
}

impl Observation {
    pub fn success(strategy: PathStrategy, stage: Stage, elapsed: Duration) -> Self {
        Self {
            strategy,
            stage,
            failure: None,
            bytes_at_failure: 0,
            elapsed_at_failure: elapsed,
            success: true,
        }
    }

    pub fn failure(strategy: PathStrategy, failure: &Failure) -> Self {
        Self {
            strategy,
            stage: failure.stage,
            failure: Some(failure.kind),
            bytes_at_failure: failure.bytes_at_failure,
            elapsed_at_failure: failure.elapsed_at_failure,
            success: false,
        }
    }
}

/// Opaque local network identity plus bounded evidence.
#[derive(Debug, Clone)]
pub struct NetworkProfile {
    identity_hash: [u8; 32],
    history: VecDeque<Observation>,
}

impl NetworkProfile {
    pub fn new(local_identity_material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zray-network-profile-v1\0");
        hasher.update(local_identity_material);
        Self {
            identity_hash: hasher.finalize().into(),
            history: VecDeque::with_capacity(HISTORY_LIMIT),
        }
    }

    pub fn identity_hash(&self) -> [u8; 32] {
        self.identity_hash
    }

    pub fn record(&mut self, observation: Observation) {
        if self.history.len() == HISTORY_LIMIT {
            self.history.pop_front();
        }
        self.history.push_back(observation);
    }

    pub fn recent(&self, strategy: PathStrategy) -> impl Iterator<Item = &Observation> {
        self.history
            .iter()
            .filter(move |observation| observation.strategy == strategy)
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    pub fn last_success(&self) -> Option<PathStrategy> {
        self.history
            .iter()
            .rev()
            .find(|observation| observation.success)
            .map(|observation| observation.strategy)
    }
}

/// Successes required at the current rung before a cheaper one is re-probed.
/// Descending too eagerly costs a failed connection every time the network is
/// merely intermittent; descending never means a client stays on the most
/// expensive disguise long after a blocking event has ended (PLAN-02 §5).
const DESCEND_AFTER_SUCCESSES: u32 = 16;

/// Consecutive failures that mark the whole access class, rather than one
/// handshake, as unavailable.
const CLASS_FATAL_FAILURES: u32 = 3;

/// What the planner decided a failure means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The rung is unchanged; the failure did not argue for a different one.
    Hold,
    /// Moved to another rung inside the same access class.
    Climb { to: PathStrategy },
    /// The endpoint family itself is unavailable; moved to the next class.
    ClassChange { to: AccessClass, at: PathStrategy },
}

/// Planner state with conservative climb/descend rules.
#[derive(Debug, Clone)]
pub struct ConnectionPlanner {
    profile: NetworkProfile,
    current: PathStrategy,
    successes_at_current: u32,
    consecutive_failures: u32,
    /// The rung a descent probe is currently testing, if any.
    probing: Option<PathStrategy>,
    /// How long the most recent time-triggered reset let a flow live.
    ///
    /// Kept because the remedy needs a *number*, not just a rung: shaping has
    /// to rotate a carrier before this deadline, and a fixed guess would be
    /// either useless on a short timeout or wasteful on a long one.
    observed_flow_lifetime: Option<Duration>,
}

impl ConnectionPlanner {
    pub fn new(local_identity_material: &[u8]) -> Self {
        Self {
            profile: NetworkProfile::new(local_identity_material),
            current: PathStrategy::DirectReality,
            successes_at_current: 0,
            consecutive_failures: 0,
            probing: None,
            observed_flow_lifetime: None,
        }
    }

    pub fn current(&self) -> PathStrategy {
        self.current
    }

    pub fn current_class(&self) -> AccessClass {
        self.current.access_class()
    }

    pub fn profile(&self) -> &NetworkProfile {
        &self.profile
    }

    pub fn successes_at_current(&self) -> u32 {
        self.successes_at_current
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// The lifetime the last time-triggered reset measured, if one has been
    /// seen. `None` means no flow-timeout evidence exists and a caller must
    /// not invent a keepalive schedule.
    pub fn observed_flow_lifetime(&self) -> Option<Duration> {
        self.observed_flow_lifetime
    }

    pub fn record_success(&mut self, stage: Stage, elapsed: Duration) {
        self.profile
            .record(Observation::success(self.current, stage, elapsed));
        self.successes_at_current = self.successes_at_current.saturating_add(1);
        self.consecutive_failures = 0;
    }

    pub fn record_failure(&mut self, failure: &Failure) -> Transition {
        self.profile
            .record(Observation::failure(self.current, failure));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.successes_at_current = 0;
        if failure.kind == FailureKind::TcpReset && is_time_triggered(failure) {
            // Keep the shortest credible observation: a middlebox that killed
            // a flow at 60s will kill one at 90s too, so rotating on the
            // longer sample would still lose connections.
            self.observed_flow_lifetime = Some(match self.observed_flow_lifetime {
                Some(previous) => previous.min(failure.elapsed_at_failure),
                None => failure.elapsed_at_failure,
            });
        }

        // A class dies as a unit: once the VPS address is blocked, no amount of
        // fingerprint rotation or fragmentation inside that class will help, and
        // climbing through the remaining rungs only wastes the user's time.
        if self.consecutive_failures >= CLASS_FATAL_FAILURES && is_class_fatal(failure.kind) {
            if let Some(class) = self.current.access_class().next() {
                let at = class.first_strategy();
                self.current = at;
                self.successes_at_current = 0;
                self.consecutive_failures = 0;
                self.probing = None;
                return Transition::ClassChange { to: class, at };
            }
        }

        if !failure.kind.suggests_interference() {
            return Transition::Hold;
        }
        let Some(next) = self.next_for_failure(failure) else {
            return Transition::Hold;
        };
        if next == self.current {
            return Transition::Hold;
        }
        // Never move backwards on a failure: a cheaper rung already failed to
        // get here, so re-selecting it would loop.
        if next < self.current {
            return Transition::Hold;
        }
        let previous_class = self.current.access_class();
        self.current = next;
        self.successes_at_current = 0;
        self.consecutive_failures = 0;
        self.probing = None;
        if next.access_class() != previous_class {
            return Transition::ClassChange {
                to: next.access_class(),
                at: next,
            };
        }
        Transition::Climb { to: next }
    }

    /// Re-probe one lower rung, but only after the current path has proven
    /// itself. Returns `None` while there is nothing cheaper to try, while the
    /// current rung has not yet earned the attempt, or while a probe is
    /// already outstanding.
    pub fn schedule_downgrade_probe(&mut self) -> Option<PathStrategy> {
        if self.probing.is_some() || self.successes_at_current < DESCEND_AFTER_SUCCESSES {
            return None;
        }
        let lower = self.current.previous()?;
        self.probing = Some(lower);
        Some(lower)
    }

    /// Report the outcome of a descent probe. Success adopts the cheaper rung;
    /// failure keeps the current one and restarts the success count, so the
    /// next attempt is again a full confidence interval away rather than
    /// immediate.
    pub fn record_probe(&mut self, strategy: PathStrategy, succeeded: bool) -> bool {
        if self.probing != Some(strategy) {
            return false;
        }
        self.probing = None;
        if succeeded {
            self.current = strategy;
            self.successes_at_current = 0;
            self.consecutive_failures = 0;
            true
        } else {
            self.successes_at_current = 0;
            false
        }
    }

    pub fn adopt_probe(&mut self, strategy: PathStrategy) {
        self.current = strategy;
        self.successes_at_current = 0;
        self.consecutive_failures = 0;
        self.probing = None;
    }

    fn next_for_failure(&self, failure: &Failure) -> Option<PathStrategy> {
        match failure.kind {
            // A reset that arrived only after the flow had lived a while is a
            // flow-timeout policy, not a matched handshake. Fragmentation
            // cannot help — the ClientHello already got through, minutes ago —
            // so the remedy is to shape the flow's lifetime instead
            // (PLAN-01 §5.2).
            FailureKind::TcpReset if is_time_triggered(failure) => {
                Some(PathStrategy::KeepaliveShaping)
            }
            // Bytes moved before the reset: the handshake was seen and matched,
            // which is what fragmentation addresses.
            FailureKind::TcpReset if failure.bytes_at_failure > 0 => {
                Some(PathStrategy::ClientHelloFragment)
            }
            // A clean timeout means nothing came back at all. Splitting the
            // ClientHello does not help when the path itself is gone.
            FailureKind::TlsTimeout | FailureKind::QuicHandshakeTimeout => {
                Some(PathStrategy::CdnWebSocket)
            }
            FailureKind::UdpBlackhole | FailureKind::UdpTimeout => Some(PathStrategy::CdnWebSocket),
            _ => self.current.next(),
        }
    }
}

/// A reset sooner than this is a handshake being matched, not flow state
/// being expired. Middleboxes that time flows out do it on the order of
/// minutes; this must stay in step with `zero_evasion::keepalive`'s own
/// credibility floor, which the runtime test in `iran_simulation` pins.
pub const MIN_CREDIBLE_FLOW_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether a reset argues for keepalive shaping rather than fragmentation.
///
/// Two things have to hold. The connection must have *completed* — a reset
/// during the handshake is the DPI matching the hello, whatever the clock
/// says. And it must have lived long enough for flow expiry to be a credible
/// explanation.
fn is_time_triggered(failure: &Failure) -> bool {
    failure.stage >= Stage::TlsCompleted && failure.elapsed_at_failure >= MIN_CREDIBLE_FLOW_TIMEOUT
}

/// Failures that indict the endpoint family rather than the disguise.
fn is_class_fatal(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::TcpTimeout
            | FailureKind::TcpUnreachable
            | FailureKind::TcpRefused
            | FailureKind::NetworkChanged
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extreme_latencies_do_not_panic_the_ewma() {
        let mut table = HealthTable::default();
        table.record_success("a", Duration::MAX);
        table.record_success("a", Duration::MAX);
        assert_eq!(table.sample("a").successes, 2);
        assert!(table.sample("a").latency.is_some());
    }

    #[test]
    fn identity_is_opaque_and_stable() {
        let a = NetworkProfile::new(b"gateway|ssid|wlan0");
        let b = NetworkProfile::new(b"gateway|ssid|wlan0");
        let c = NetworkProfile::new(b"other");
        assert_eq!(a.identity_hash(), b.identity_hash());
        assert_ne!(a.identity_hash(), c.identity_hash());
    }

    #[test]
    fn byte_threshold_resets_escalate_to_fragmentation() {
        let mut planner = ConnectionPlanner::new(b"local");
        let failure =
            Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred).with_bytes(4096);
        planner.record_failure(&failure);
        assert_eq!(planner.current(), PathStrategy::ClientHelloFragment);
    }

    #[test]
    fn clean_tls_timeout_changes_class() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.record_failure(&Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted));
        assert_eq!(planner.current(), PathStrategy::CdnWebSocket);
    }

    #[test]
    fn a_reset_after_a_long_clean_session_argues_for_keepalive_shaping() {
        // The handshake completed and the flow carried traffic for two
        // minutes. Splitting the ClientHello cannot help something that
        // already got through; what died was the flow's state entry.
        let mut planner = ConnectionPlanner::new(b"local");
        let failure = Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred)
            .with_bytes(8 * 1024 * 1024)
            .with_elapsed(Duration::from_secs(120));
        assert_eq!(
            planner.record_failure(&failure),
            Transition::Climb {
                to: PathStrategy::KeepaliveShaping
            }
        );
        assert_eq!(
            planner.observed_flow_lifetime(),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn the_same_reset_kind_gets_opposite_remedies_from_its_timing() {
        // This is the distinction PLAN-01 §5.2 exists for: identical
        // FailureKind, identical stage, opposite correct answers.
        let mut early = ConnectionPlanner::new(b"local");
        early.record_failure(
            &Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred)
                .with_bytes(4096)
                .with_elapsed(Duration::from_millis(300)),
        );
        assert_eq!(early.current(), PathStrategy::ClientHelloFragment);

        let mut late = ConnectionPlanner::new(b"local");
        late.record_failure(
            &Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred)
                .with_bytes(4096)
                .with_elapsed(Duration::from_secs(90)),
        );
        assert_eq!(late.current(), PathStrategy::KeepaliveShaping);
    }

    #[test]
    fn a_reset_during_the_handshake_is_never_read_as_a_flow_timeout() {
        // A slow network can make even a handshake reset arrive late. What
        // rules it out as flow expiry is that the connection never completed.
        let mut planner = ConnectionPlanner::new(b"local");
        let failure = Failure::new(FailureKind::TcpReset, Stage::TlsStarted)
            .with_bytes(517)
            .with_elapsed(Duration::from_secs(120));
        planner.record_failure(&failure);
        assert_eq!(planner.current(), PathStrategy::ClientHelloFragment);
        assert_eq!(planner.observed_flow_lifetime(), None);
    }

    #[test]
    fn the_shortest_observed_flow_lifetime_is_the_one_kept() {
        let mut planner = ConnectionPlanner::new(b"local");
        let long = Failure::new(FailureKind::TcpReset, Stage::BidirectionalConfirmed)
            .with_elapsed(Duration::from_secs(300));
        let short = Failure::new(FailureKind::TcpReset, Stage::BidirectionalConfirmed)
            .with_elapsed(Duration::from_secs(60));
        planner.record_failure(&long);
        planner.record_failure(&short);
        planner.record_failure(&long);
        // Rotating on the 300s sample would still lose every flow the 60s
        // threshold kills.
        assert_eq!(
            planner.observed_flow_lifetime(),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn keepalive_shaping_is_cheaper_than_fragmentation_on_the_ladder() {
        assert!(PathStrategy::KeepaliveShaping < PathStrategy::ClientHelloFragment);
        assert!(PathStrategy::KeepaliveShaping > PathStrategy::FingerprintRotation);
        assert_eq!(
            PathStrategy::KeepaliveShaping.access_class(),
            AccessClass::DirectReality
        );
    }

    #[test]
    fn the_compact_encoding_round_trips_every_rung() {
        // The runtime stores the current rung in an AtomicU8. A rung added
        // without updating that encoding would silently select another one.
        for strategy in PathStrategy::ALL {
            assert_eq!(PathStrategy::from_u8(strategy.as_u8()), strategy);
        }
        assert_eq!(
            PathStrategy::from_u8(PathStrategy::ALL.len() as u8),
            PathStrategy::DirectReality
        );
    }

    #[test]
    fn ladder_groups_strategies_into_access_classes() {
        assert_eq!(
            PathStrategy::ClientHelloFragment.access_class(),
            AccessClass::DirectReality
        );
        assert_eq!(
            PathStrategy::CdnCleanIp.access_class(),
            AccessClass::CdnFronted
        );
        assert_eq!(
            PathStrategy::AmneziaWireguard.access_class(),
            AccessClass::WarpTunnel
        );
    }

    #[test]
    fn history_is_bounded() {
        let mut profile = NetworkProfile::new(b"local");
        for _ in 0..(HISTORY_LIMIT + 10) {
            profile.record(Observation::success(
                PathStrategy::DirectReality,
                Stage::BidirectionalConfirmed,
                Duration::from_millis(1),
            ));
        }
        assert_eq!(profile.history_len(), HISTORY_LIMIT);
    }

    fn tcp_timeout() -> Failure {
        Failure::new(FailureKind::TcpTimeout, Stage::SocketConnected)
    }

    #[test]
    fn a_dead_access_class_moves_to_the_next_class_rather_than_up_its_own_ladder() {
        let mut planner = ConnectionPlanner::new(b"local");
        // One or two connect timeouts are ordinary; they must not cost a class.
        assert_eq!(planner.record_failure(&tcp_timeout()), Transition::Hold);
        assert_eq!(planner.record_failure(&tcp_timeout()), Transition::Hold);
        assert_eq!(planner.current_class(), AccessClass::DirectReality);

        // The third says the address family itself is gone.
        assert_eq!(
            planner.record_failure(&tcp_timeout()),
            Transition::ClassChange {
                to: AccessClass::CdnFronted,
                at: PathStrategy::CdnWebSocket,
            }
        );
        assert_eq!(planner.current(), PathStrategy::CdnWebSocket);
    }

    #[test]
    fn a_class_change_restarts_at_the_cheapest_rung_of_the_new_class() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::SniDesync);
        for _ in 0..CLASS_FATAL_FAILURES {
            planner.record_failure(&tcp_timeout());
        }
        // Not CdnAlternatePort or CdnCleanIp: those answer questions the old
        // class raised, and their cost has not been justified here.
        assert_eq!(planner.current(), PathStrategy::CdnWebSocket);
    }

    #[test]
    fn the_last_class_has_nowhere_to_fall_back_to() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::AmneziaWireguard);
        for _ in 0..(CLASS_FATAL_FAILURES + 2) {
            planner.record_failure(&tcp_timeout());
        }
        assert_eq!(planner.current(), PathStrategy::AmneziaWireguard);
    }

    #[test]
    fn a_success_resets_the_class_fatal_counter() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.record_failure(&tcp_timeout());
        planner.record_failure(&tcp_timeout());
        planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(30));
        planner.record_failure(&tcp_timeout());
        assert_eq!(planner.current_class(), AccessClass::DirectReality);
    }

    #[test]
    fn descent_is_earned_by_sustained_success_and_not_offered_before() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::ClientHelloFragment);
        assert_eq!(planner.schedule_downgrade_probe(), None);
        for _ in 0..(DESCEND_AFTER_SUCCESSES - 1) {
            planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(20));
        }
        assert_eq!(planner.schedule_downgrade_probe(), None);
        planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(20));
        assert_eq!(
            planner.schedule_downgrade_probe(),
            Some(PathStrategy::KeepaliveShaping)
        );
        // Only one probe outstanding at a time.
        assert_eq!(planner.schedule_downgrade_probe(), None);
    }

    #[test]
    fn a_successful_descent_probe_adopts_the_cheaper_rung() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::CdnWebSocket);
        for _ in 0..DESCEND_AFTER_SUCCESSES {
            planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(20));
        }
        let probe = planner.schedule_downgrade_probe().unwrap();
        assert_eq!(probe, PathStrategy::RealityXhttp);
        assert!(planner.record_probe(probe, true));
        assert_eq!(planner.current(), PathStrategy::RealityXhttp);
    }

    #[test]
    fn a_failed_descent_probe_keeps_the_working_rung_and_re_earns_the_next_attempt() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::CdnWebSocket);
        for _ in 0..DESCEND_AFTER_SUCCESSES {
            planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(20));
        }
        let probe = planner.schedule_downgrade_probe().unwrap();
        assert!(!planner.record_probe(probe, false));
        assert_eq!(planner.current(), PathStrategy::CdnWebSocket);
        // The next attempt is a full confidence interval away, not immediate.
        assert_eq!(planner.schedule_downgrade_probe(), None);
        assert_eq!(planner.successes_at_current(), 0);
    }

    #[test]
    fn a_stale_probe_result_is_ignored() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::CdnWebSocket);
        // No probe was scheduled, so a report about one must change nothing.
        assert!(!planner.record_probe(PathStrategy::DirectReality, true));
        assert_eq!(planner.current(), PathStrategy::CdnWebSocket);
    }

    #[test]
    fn a_failure_never_selects_a_cheaper_rung_that_already_failed() {
        let mut planner = ConnectionPlanner::new(b"local");
        planner.adopt_probe(PathStrategy::CdnCleanIp);
        // TcpReset with bytes argues for fragmentation, which is below the
        // current rung — taking it would loop back through what already failed.
        let failure =
            Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred).with_bytes(4096);
        assert_eq!(planner.record_failure(&failure), Transition::Hold);
        assert_eq!(planner.current(), PathStrategy::CdnCleanIp);
    }

    #[test]
    fn a_climb_inside_one_class_is_reported_as_a_climb() {
        let mut planner = ConnectionPlanner::new(b"local");
        let failure =
            Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred).with_bytes(4096);
        assert_eq!(
            planner.record_failure(&failure),
            Transition::Climb {
                to: PathStrategy::ClientHelloFragment
            }
        );
    }

    #[test]
    fn a_tls_timeout_is_reported_as_a_class_change() {
        let mut planner = ConnectionPlanner::new(b"local");
        assert_eq!(
            planner.record_failure(&Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted)),
            Transition::ClassChange {
                to: AccessClass::CdnFronted,
                at: PathStrategy::CdnWebSocket,
            }
        );
    }

    #[test]
    fn a_udp_timeout_uses_the_cdn_escape_branch() {
        let mut planner = ConnectionPlanner::new(b"local");
        assert_eq!(
            planner.record_failure(&Failure::new(FailureKind::UdpTimeout, Stage::RequestSent)),
            Transition::ClassChange {
                to: AccessClass::CdnFronted,
                at: PathStrategy::CdnWebSocket,
            }
        );
    }

    #[test]
    fn a_mid_session_network_change_marks_the_access_class_after_confirmation() {
        let mut planner = ConnectionPlanner::new(b"local");
        let failure = Failure::new(FailureKind::NetworkChanged, Stage::PayloadTransferred);
        assert_eq!(planner.record_failure(&failure), Transition::Hold);
        assert_eq!(planner.record_failure(&failure), Transition::Hold);
        assert_eq!(
            planner.record_failure(&failure),
            Transition::ClassChange {
                to: AccessClass::CdnFronted,
                at: PathStrategy::CdnWebSocket,
            }
        );
    }

    #[test]
    fn access_classes_form_an_ordered_ladder() {
        assert_eq!(
            AccessClass::DirectReality.next(),
            Some(AccessClass::CdnFronted)
        );
        assert_eq!(
            AccessClass::CdnFronted.next(),
            Some(AccessClass::WarpTunnel)
        );
        assert_eq!(AccessClass::WarpTunnel.next(), None);
        for class in AccessClass::ALL {
            assert_eq!(class.first_strategy().access_class(), class);
        }
    }

    #[test]
    fn health_selection_prefers_low_latency_and_penalizes_failures() {
        let mut table = HealthTable::default();
        table.record_success("slow", Duration::from_millis(200));
        table.record_success("fast", Duration::from_millis(20));
        assert_eq!(
            table.choose(
                BalancerHealthStrategy::LeastPing,
                &[Arc::from("slow"), Arc::from("fast")],
                0
            ),
            1
        );
        table.record_failure("fast");
        table.record_failure("fast");
        assert_eq!(
            table.choose(
                BalancerHealthStrategy::LeastPing,
                &[Arc::from("slow"), Arc::from("fast")],
                0
            ),
            0
        );
    }
}
