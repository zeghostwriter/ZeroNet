//! Keepalive shaping — the remedy for a *time*-triggered reset.
//!
//! PLAN-01 §5.2 draws a distinction the rest of the corpus does not:
//!
//! > when a path dies, does it die at a byte threshold or a time threshold?
//! > Reset-after-N-bytes indicates throughput-based DPI and argues for
//! > fragmentation/padding. Reset-after-T-seconds with clean handshake
//! > indicates flow-timeout policy and argues for keepalive shaping. Same
//! > `CONNECTION_RESET`, opposite remedies.
//!
//! Fragmentation is useless against a flow-timeout policy: the ClientHello
//! already got through, was already accepted, and the flow already carried
//! traffic. What killed it was its *shape over time* — either it sat idle long
//! enough to be collected, or it simply outlived the middlebox's state entry.
//!
//! So this module shapes time, in the two ways a client actually can:
//!
//! 1. **Idle probing.** A carrier that has been silent longer than
//!    `idle_after` emits one keepalive frame. This costs a few bytes a minute
//!    and keeps the flow from looking abandoned.
//! 2. **Proactive retirement.** A carrier that has reached `max_flow_lifetime`
//!    is marked due for replacement *before* the observed reset deadline.
//!    Retirement is deliberately advisory: existing sessions finish on the old
//!    carrier and only new ones get a fresh one. Tearing a live transfer down
//!    to avoid a reset would deliver exactly the outcome it was avoiding.
//!
//! The frame itself is supplied by the caller, because only the carrier knows
//! what a legal no-op looks like on its wire — a WebSocket Ping, a mux
//! `KeepAlive` status, nothing at all. Inventing padding bytes for a carrier
//! with no no-op frame would corrupt the tunnel, so a carrier that cannot
//! express one simply does not get idle probes and keeps retirement only.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// A reset sooner than this is not credible evidence of a flow-timeout policy.
///
/// Middleboxes that expire flow state do it on the order of minutes; a reset a
/// few seconds in is a handshake being matched, which is what fragmentation
/// addresses. Treating those as timeouts would deploy the wrong remedy and,
/// worse, would keep the client from ever climbing to the right one.
pub const MIN_CREDIBLE_FLOW_TIMEOUT: Duration = Duration::from_secs(15);

/// Fraction of the observed lifetime at which a carrier is retired.
///
/// The observed value is one sample of a threshold that may itself jitter, so
/// rotating at the edge of it would still lose flows. Six tenths leaves room
/// for both jitter and the time a replacement handshake takes.
const RETIRE_AT_FRACTION: u32 = 6;
const RETIRE_OF: u32 = 10;

const MIN_IDLE_PROBE: Duration = Duration::from_secs(2);
const MAX_IDLE_PROBE: Duration = Duration::from_secs(30);
const MIN_LIFETIME: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepalivePolicy {
    /// Emit one keepalive frame after this much write idleness.
    pub idle_after: Duration,
    /// Mark the carrier due for replacement once it reaches this age.
    /// `None` keeps carriers indefinitely and applies idle probing only.
    pub max_flow_lifetime: Option<Duration>,
}

impl Default for KeepalivePolicy {
    /// A conservative shape for a network that has shown a flow timeout but
    /// has not yet told us where it is.
    fn default() -> Self {
        Self {
            idle_after: Duration::from_secs(15),
            max_flow_lifetime: Some(Duration::from_secs(120)),
        }
    }
}

impl KeepalivePolicy {
    /// Derive a policy from one observed time-triggered reset.
    ///
    /// Returns `None` when the observation is not credible evidence of a flow
    /// timeout, so a caller cannot accidentally deploy this against a
    /// handshake-matching reset.
    pub fn from_observed_reset(elapsed_at_failure: Duration) -> Option<Self> {
        if elapsed_at_failure < MIN_CREDIBLE_FLOW_TIMEOUT {
            return None;
        }
        let lifetime = (elapsed_at_failure * RETIRE_AT_FRACTION / RETIRE_OF).max(MIN_LIFETIME);
        let idle_after = (lifetime / 4).clamp(MIN_IDLE_PROBE, MAX_IDLE_PROBE);
        Some(Self {
            idle_after,
            max_flow_lifetime: Some(lifetime),
        })
    }

    /// Idle probing only, for a carrier that should never be rotated.
    pub fn idle_only(idle_after: Duration) -> Self {
        Self {
            idle_after,
            max_flow_lifetime: None,
        }
    }
}

/// What the shaper wants to happen next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveAction {
    /// Nothing is due.
    Idle,
    /// The carrier has been silent long enough; send one keepalive frame.
    Probe,
    /// The carrier has reached its lifetime and should not take new sessions.
    Retire,
}

/// The pure timing decision, separated from any I/O so it can be tested
/// against an explicit clock rather than against wall time.
#[derive(Debug, Clone, Copy)]
pub struct KeepaliveState {
    policy: KeepalivePolicy,
    opened_at: Instant,
    last_activity: Instant,
}

impl KeepaliveState {
    pub fn new(policy: KeepalivePolicy, now: Instant) -> Self {
        Self {
            policy,
            opened_at: now,
            last_activity: now,
        }
    }

    pub fn policy(&self) -> KeepalivePolicy {
        self.policy
    }

    /// Record real traffic. Any byte in either direction proves the flow is
    /// not idle, so both directions reset the idle timer — a download with no
    /// uploads is still a live flow to the middlebox watching it.
    pub fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.opened_at)
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_activity)
    }

    /// Retirement outranks probing: once a carrier is past its lifetime, one
    /// more keepalive frame buys nothing and the answer is a fresh carrier.
    pub fn action(&self, now: Instant) -> KeepaliveAction {
        if self
            .policy
            .max_flow_lifetime
            .is_some_and(|limit| self.age(now) >= limit)
        {
            return KeepaliveAction::Retire;
        }
        if self.idle_for(now) >= self.policy.idle_after {
            return KeepaliveAction::Probe;
        }
        KeepaliveAction::Idle
    }

    pub fn due_for_retirement(&self, now: Instant) -> bool {
        matches!(self.action(now), KeepaliveAction::Retire)
    }

    /// When to look again. `None` once the carrier is already retired.
    pub fn next_check(&self, now: Instant) -> Option<Duration> {
        match self.action(now) {
            KeepaliveAction::Retire => None,
            _ => {
                let until_probe = self.policy.idle_after.saturating_sub(self.idle_for(now));
                let until_retire = self
                    .policy
                    .max_flow_lifetime
                    .map(|limit| limit.saturating_sub(self.age(now)));
                Some(match until_retire {
                    Some(retire) => until_probe.min(retire),
                    None => until_probe,
                })
            }
        }
    }
}

/// A carrier that can put a legal no-op on its own wire.
///
/// The carrier does the sending rather than handing bytes up, because on every
/// real carrier the no-op frame is *stateful*: a TLS 1.3 record has to be
/// sealed with the connection's own write key and nonce counter, and a client
/// WebSocket frame needs a fresh mask. Bytes produced outside the carrier and
/// written back through it would be sealed or framed a second time, which
/// desynchronises the stream — so the trait passes the responsibility down
/// instead of the bytes up.
pub trait KeepaliveCarrier {
    /// Emit one no-op frame.
    ///
    /// `Ready(Ok(false))` means this carrier has no legal no-op and nothing
    /// went on the wire; that is a normal answer, not an error. Inventing
    /// padding for such a carrier would corrupt the tunnel, so the shaper
    /// falls back to retirement alone.
    fn poll_keepalive(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>>;
}

/// A carrier wrapper that emits idle probes and tracks retirement.
///
/// Probes are emitted from `poll_read`, which is where a proxied flow actually
/// waits: the relay parks on the read side of each half and only wakes when
/// there is something to move. A shaper that only acted inside `poll_write`
/// would fire exactly when the flow was already not idle.
pub struct KeepaliveStream<S> {
    inner: S,
    state: KeepaliveState,
    timer: Option<Pin<Box<Sleep>>>,
    probes_sent: u64,
    /// Set once the carrier reports it has no legal no-op, so the shaper stops
    /// asking and settles for retirement alone.
    probing_unavailable: bool,
}

impl<S> KeepaliveStream<S> {
    pub fn new(inner: S, policy: KeepalivePolicy) -> Self {
        Self {
            inner,
            state: KeepaliveState::new(policy, Instant::now()),
            timer: None,
            probes_sent: 0,
            probing_unavailable: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn state(&self) -> &KeepaliveState {
        &self.state
    }

    /// Whether the dispatcher should stop handing new sessions to this
    /// carrier. Advisory: sessions already on it are left alone.
    pub fn due_for_retirement(&self) -> bool {
        self.state.due_for_retirement(Instant::now())
    }

    /// How many idle probes this carrier has emitted. Exposed so a test can
    /// prove the shaping actually happened rather than that bytes flowed.
    pub fn probes_sent(&self) -> u64 {
        self.probes_sent
    }

    /// Whether the carrier told us it has no legal no-op frame.
    pub fn probing_unavailable(&self) -> bool {
        self.probing_unavailable
    }
}

impl<S: KeepaliveCarrier + Unpin> KeepaliveStream<S> {
    fn poll_send_probe(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_keepalive(cx) {
            Poll::Ready(Ok(sent)) => {
                if sent {
                    self.probes_sent += 1;
                } else {
                    self.probing_unavailable = true;
                }
                // Either way the idle timer restarts: a carrier that cannot
                // probe must not spin asking every poll.
                self.state.note_activity(Instant::now());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + KeepaliveCarrier + Unpin> AsyncRead for KeepaliveStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() != before {
                    this.state.note_activity(Instant::now());
                }
                // The timer is kept armed: it may now fire early, which only
                // costs one recheck per idle period, whereas dropping it here
                // would allocate and register a fresh one every time a busy
                // flow's read goes pending.
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }

        // The read side is parked. This is the idle case the shaper exists
        // for, so arm a timer and probe when it fires.
        loop {
            let now = Instant::now();
            match this.state.action(now) {
                KeepaliveAction::Probe if !this.probing_unavailable => {
                    match this.poll_send_probe(cx) {
                        Poll::Ready(Ok(())) => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                // Retired carriers are not torn down here: the session on this
                // stream is still the user's, and dropping it would cause the
                // very interruption the policy is trying to avoid. A carrier
                // with no no-op frame parks for the same reason.
                KeepaliveAction::Retire | KeepaliveAction::Probe => return Poll::Pending,
                KeepaliveAction::Idle => {
                    let Some(wait) = this.state.next_check(now) else {
                        return Poll::Pending;
                    };
                    let deadline = now + wait;
                    let timer = match this.timer.as_mut() {
                        Some(timer) => {
                            // An earlier, still-pending deadline is harmless:
                            // it fires, and this loop re-arms from the fresh
                            // state. A fired timer must be re-armed, or the
                            // next poll would see it ready again and spin.
                            if timer.is_elapsed() || timer.deadline() > deadline {
                                timer.as_mut().reset(deadline);
                            }
                            timer
                        }
                        None => this
                            .timer
                            .insert(Box::pin(tokio::time::sleep_until(deadline))),
                    };
                    return match timer.as_mut().poll(cx) {
                        Poll::Ready(()) => continue,
                        Poll::Pending => Poll::Pending,
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for KeepaliveStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                this.state.note_activity(Instant::now());
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Adapter for a carrier with no legal no-op frame — a raw TCP stream, an
/// HTTPUpgrade tunnel, anything whose wire is undelimited payload.
///
/// Wrapping such a carrier still buys proactive retirement, which is the half
/// of keepalive shaping that does not need a frame at all.
#[derive(Debug, Clone, Copy)]
pub struct NoKeepalive<S>(pub S);

impl<S> KeepaliveCarrier for NoKeepalive<S> {
    fn poll_keepalive(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for NoKeepalive<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoKeepalive<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn a_reset_too_early_to_be_a_flow_timeout_yields_no_policy() {
        // This is a handshake being matched. Deploying keepalives here would
        // spend the user's time on a remedy that cannot work.
        assert_eq!(
            KeepalivePolicy::from_observed_reset(Duration::from_secs(2)),
            None
        );
        assert_eq!(
            KeepalivePolicy::from_observed_reset(
                MIN_CREDIBLE_FLOW_TIMEOUT - Duration::from_millis(1)
            ),
            None
        );
    }

    #[test]
    fn a_credible_timeout_retires_well_before_the_observed_deadline() {
        let observed = Duration::from_secs(300);
        let policy = KeepalivePolicy::from_observed_reset(observed).expect("credible");
        let lifetime = policy.max_flow_lifetime.expect("lifetime set");
        assert!(
            lifetime < observed,
            "retiring at or after the observed deadline would still lose the flow"
        );
        assert_eq!(lifetime, Duration::from_secs(180));
        // And the idle probe has to be frequent enough to matter within it.
        assert!(policy.idle_after < lifetime);
        assert_eq!(policy.idle_after, MAX_IDLE_PROBE);
    }

    #[test]
    fn the_idle_probe_interval_is_clamped_at_both_ends() {
        let short = KeepalivePolicy::from_observed_reset(MIN_CREDIBLE_FLOW_TIMEOUT).unwrap();
        assert!(short.idle_after >= MIN_IDLE_PROBE);
        let long = KeepalivePolicy::from_observed_reset(Duration::from_secs(3600)).unwrap();
        assert!(long.idle_after <= MAX_IDLE_PROBE);
    }

    #[test]
    fn activity_defers_the_probe_and_silence_brings_it_due() {
        let start = Instant::now();
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(10),
            max_flow_lifetime: Some(Duration::from_secs(100)),
        };
        let mut state = KeepaliveState::new(policy, start);
        assert_eq!(state.action(start), KeepaliveAction::Idle);
        assert_eq!(
            state.action(start + Duration::from_secs(9)),
            KeepaliveAction::Idle
        );
        assert_eq!(
            state.action(start + Duration::from_secs(10)),
            KeepaliveAction::Probe
        );
        state.note_activity(start + Duration::from_secs(10));
        assert_eq!(
            state.action(start + Duration::from_secs(19)),
            KeepaliveAction::Idle
        );
    }

    #[test]
    fn retirement_outranks_probing() {
        let start = Instant::now();
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(10),
            max_flow_lifetime: Some(Duration::from_secs(30)),
        };
        let state = KeepaliveState::new(policy, start);
        // At 30s the carrier is both idle and expired. One more probe would
        // not save it, so the answer must be a fresh carrier.
        assert_eq!(
            state.action(start + Duration::from_secs(30)),
            KeepaliveAction::Retire
        );
        assert!(state.due_for_retirement(start + Duration::from_secs(31)));
    }

    #[test]
    fn a_busy_carrier_still_retires_on_age() {
        let start = Instant::now();
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(10),
            max_flow_lifetime: Some(Duration::from_secs(30)),
        };
        let mut state = KeepaliveState::new(policy, start);
        // Constant traffic keeps it out of the probe branch entirely, but a
        // flow-timeout policy does not care how busy a flow is.
        for second in 1..=30 {
            state.note_activity(start + Duration::from_secs(second));
        }
        assert_eq!(
            state.action(start + Duration::from_secs(30)),
            KeepaliveAction::Retire
        );
    }

    #[test]
    fn a_policy_with_no_lifetime_never_retires() {
        let start = Instant::now();
        let state = KeepaliveState::new(KeepalivePolicy::idle_only(Duration::from_secs(5)), start);
        assert_eq!(
            state.action(start + Duration::from_secs(86_400)),
            KeepaliveAction::Probe
        );
        assert!(!state.due_for_retirement(start + Duration::from_secs(86_400)));
    }

    #[test]
    fn next_check_never_overshoots_either_deadline() {
        let start = Instant::now();
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(40),
            max_flow_lifetime: Some(Duration::from_secs(50)),
        };
        let state = KeepaliveState::new(policy, start);
        // Retirement is nearer than the probe, so that is what we wake for.
        assert_eq!(state.next_check(start), Some(Duration::from_secs(40)));
        let mut later = state;
        later.note_activity(start + Duration::from_secs(45));
        assert_eq!(
            later.next_check(start + Duration::from_secs(45)),
            Some(Duration::from_secs(5))
        );
    }

    /// A carrier stand-in that frames its own no-op, the way a real TLS or
    /// WebSocket carrier does — a distinctive two-byte marker the test can
    /// count on the wire without pulling those crates in here.
    struct TestCarrier<S> {
        inner: S,
        counter: u8,
    }

    impl<S> TestCarrier<S> {
        fn new(inner: S) -> Self {
            Self { inner, counter: 0 }
        }
    }

    impl<S: AsyncWrite + Unpin> KeepaliveCarrier for TestCarrier<S> {
        fn poll_keepalive(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            let this = self.get_mut();
            this.counter = this.counter.wrapping_add(1);
            let frame = [0x89u8, this.counter];
            match Pin::new(&mut this.inner).poll_write(cx, &frame) {
                Poll::Ready(Ok(n)) if n == frame.len() => Poll::Ready(Ok(true)),
                Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short keepalive frame",
                ))),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for TestCarrier<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for TestCarrier<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_carrier_emits_probes_without_the_peer_writing_anything() {
        let (mut peer, local) = tokio::io::duplex(4096);
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(10),
            max_flow_lifetime: None,
        };
        let mut shaped = KeepaliveStream::new(TestCarrier::new(local), policy);

        // The relay parks on the read side; nothing is ever sent to it.
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let _ = shaped.read(&mut buf).await;
        });

        let mut seen = Vec::new();
        while seen.len() < 4 {
            let mut buf = [0u8; 2];
            match tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut buf)).await {
                Ok(Ok(_)) => seen.push(buf),
                _ => break,
            }
        }
        assert!(
            seen.len() >= 3,
            "an idle carrier should keep probing, saw {} frames",
            seen.len()
        );
        // Each probe is a fresh frame, not a replayed buffer.
        assert_eq!(seen[0][0], 0x89);
        assert_ne!(seen[0][1], seen[1][1]);
        reader.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn real_traffic_suppresses_probes_entirely() {
        let (mut peer, local) = tokio::io::duplex(4096);
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(10),
            max_flow_lifetime: None,
        };
        let mut shaped = KeepaliveStream::new(TestCarrier::new(local), policy);

        let pump = tokio::spawn(async move {
            for _ in 0..10 {
                peer.write_all(b"payload").await.unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            peer
        });

        let mut buf = [0u8; 7];
        for _ in 0..10 {
            shaped.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"payload");
        }
        assert_eq!(
            shaped.probes_sent(),
            0,
            "a flow carrying traffic every 5s is not idle at a 10s threshold"
        );
        pump.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_carrier_with_no_legal_no_op_frame_puts_nothing_on_the_wire() {
        let (mut peer, local) = tokio::io::duplex(4096);
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(5),
            max_flow_lifetime: None,
        };
        let mut shaped = KeepaliveStream::new(NoKeepalive(local), policy);

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let _ = shaped.read(&mut buf).await;
        });

        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(60), peer.read(&mut buf)).await;
        assert!(
            result.is_err(),
            "a carrier with no no-op frame must not invent padding bytes"
        );
        reader.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_aged_carrier_reports_itself_due_for_retirement() {
        let (_peer, local) = tokio::io::duplex(64);
        let policy = KeepalivePolicy {
            idle_after: Duration::from_secs(600),
            max_flow_lifetime: Some(Duration::from_secs(30)),
        };
        let shaped = KeepaliveStream::new(NoKeepalive(local), policy);
        assert!(!shaped.due_for_retirement());
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(shaped.due_for_retirement());
    }
}
