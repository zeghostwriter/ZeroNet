//! Congestion control for the QUIC carriers beyond quinn's default: Hysteria's
//! Brutal, and a controller that can be switched to it after the connection
//! exists.
//!
//! How this works. Brutal sends at a rate you tell it, not at the rate it
//! thinks the path can take. On a path with random loss (a congested or
//! throttled international link) a loss-based controller reads every dropped
//! packet as "slow down" and collapses; Brutal instead assumes the loss is not
//! its fault, and compensates: the window is `rate × RTT ÷ ack-rate`, where
//! the ack rate is the share of packets recently delivered, so a link that
//! loses 20% is fed 25% extra and still delivers the target. It is selfish by
//! design, which is why Hysteria makes the client name a rate and the server
//! cap it.
//!
//! Hysteria 2 decides the controller *after* the connection is up: the
//! client's authentication request names the rate it wants to receive
//! (`Hysteria-CC-RX`), the answer names the rate the server wants to receive,
//! and each end then sends at the smaller of what it is allowed and what the
//! other can take. A QUIC connection is built with its controller already
//! chosen, so [`SwitchableFactory`] builds one that starts as a normal
//! controller and is switched to Brutal through a [`CongestionHandle`] once
//! the rate is known.
//!
//! The rule it keeps: a rate of zero means "not set", and a switchable
//! controller with no rate behaves exactly as its inner controller does.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, NewRenoConfig};
use quinn_proto::RttEstimator;

/// The least a loss-compensated window may count on arriving, as a share of
/// what is sent. Below it the window stops growing (a path that drops more
/// than 20% is not a path Brutal can fix by sending more).
const MIN_ACK_RATE: f64 = 0.8;
/// Seconds of history the ack rate is measured over.
const WINDOW_SLOTS: usize = 5;
/// Bytes that must have been seen before the measured ack rate is believed.
const MIN_SAMPLE_BYTES: u64 = 50 * 1200;
/// The smallest window, so a quiet connection can still send a few packets.
const MIN_WINDOW: u64 = 10 * 1200;

/// Where the rate to send at is set once the peer has answered.
#[derive(Clone, Debug, Default)]
pub struct CongestionHandle(Arc<AtomicU64>);

impl CongestionHandle {
    /// Send at `bytes_per_second` from now on; 0 returns to the inner
    /// controller.
    pub fn set_rate(&self, bytes_per_second: u64) {
        self.0.store(bytes_per_second, Ordering::Relaxed);
    }

    pub fn rate(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The share of recent bytes that were delivered, over [`WINDOW_SLOTS`]
/// one-second slots.
#[derive(Clone, Debug)]
struct AckRate {
    slots: VecDeque<(Instant, u64, u64)>,
}

impl AckRate {
    fn new() -> Self {
        Self {
            slots: VecDeque::new(),
        }
    }

    fn slot(&mut self, now: Instant) -> &mut (Instant, u64, u64) {
        let fresh = self
            .slots
            .back()
            .is_none_or(|(start, _, _)| now.duration_since(*start) >= Duration::from_secs(1));
        if fresh {
            self.slots.push_back((now, 0, 0));
            while self.slots.len() > WINDOW_SLOTS {
                self.slots.pop_front();
            }
        }
        self.slots.back_mut().expect("a slot was just pushed")
    }

    fn acked(&mut self, now: Instant, bytes: u64) {
        self.slot(now).1 += bytes;
    }

    fn lost(&mut self, now: Instant, bytes: u64) {
        self.slot(now).2 += bytes;
    }

    /// 1.0 until enough has been seen, then the delivered share, never below
    /// [`MIN_ACK_RATE`].
    fn rate(&self) -> f64 {
        let (acked, lost) = self
            .slots
            .iter()
            .fold((0u64, 0u64), |(a, l), (_, acked, lost)| {
                (a + acked, l + lost)
            });
        if acked + lost < MIN_SAMPLE_BYTES {
            return 1.0;
        }
        (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
    }
}

/// Brutal itself: a window sized to carry `rate` through the measured RTT.
#[derive(Clone, Debug)]
pub struct Brutal {
    rate: Arc<AtomicU64>,
    ack_rate: AckRate,
    rtt: Duration,
    mtu: u16,
}

impl Brutal {
    fn new(rate: Arc<AtomicU64>, mtu: u16) -> Self {
        Self {
            rate,
            ack_rate: AckRate::new(),
            rtt: Duration::ZERO,
            mtu,
        }
    }

    /// Bytes in flight that carry `bytes_per_second` through `rtt`, with the
    /// loss share `ack_rate` made up for.
    pub fn window_for(bytes_per_second: u64, rtt: Duration, ack_rate: f64) -> u64 {
        if rtt.is_zero() {
            return MIN_WINDOW;
        }
        let window = bytes_per_second as f64 * rtt.as_secs_f64() / ack_rate.max(MIN_ACK_RATE);
        (window as u64).max(MIN_WINDOW)
    }

    fn window_now(&self) -> u64 {
        Self::window_for(
            self.rate.load(Ordering::Relaxed),
            self.rtt,
            self.ack_rate.rate(),
        )
    }
}

/// A controller that is `inner` until a rate is set, then Brutal at that rate.
/// Both always see every event, so the one switched to has current numbers.
pub struct Switchable {
    inner: Box<dyn Controller>,
    brutal: Brutal,
    rate: Arc<AtomicU64>,
}

impl Controller for Switchable {
    fn on_sent(&mut self, now: std::time::Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: std::time::Instant,
        sent: std::time::Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.brutal.rtt = rtt.get();
        self.brutal.ack_rate.acked(now, bytes);
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: std::time::Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: std::time::Instant,
        sent: std::time::Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.brutal.ack_rate.lost(now, lost_bytes);
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.brutal.mtu = new_mtu;
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.rate.load(Ordering::Relaxed) == 0 {
            self.inner.window()
        } else {
            self.brutal.window_now()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            brutal: self.brutal.clone(),
            rate: Arc::clone(&self.rate),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Builds [`Switchable`] controllers around a chosen inner algorithm, all
/// switched together by one [`CongestionHandle`].
pub struct SwitchableFactory {
    inner: Arc<dyn ControllerFactory + Send + Sync>,
    rate: Arc<AtomicU64>,
}

impl SwitchableFactory {
    /// `inner` is what the connection uses until a rate is set: BBR, or
    /// NewReno, or quinn's default when `None`.
    pub fn new(
        inner: Option<Arc<dyn ControllerFactory + Send + Sync>>,
    ) -> (Arc<Self>, CongestionHandle) {
        let handle = CongestionHandle::default();
        let factory = Arc::new(Self {
            inner: inner.unwrap_or_else(|| Arc::new(NewRenoConfig::default())),
            rate: Arc::clone(&handle.0),
        });
        (factory, handle)
    }
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Switchable {
            inner: Arc::clone(&self.inner).build(now, current_mtu),
            brutal: Brutal::new(Arc::clone(&self.rate), current_mtu),
            rate: Arc::clone(&self.rate),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_carries_the_rate_through_the_round_trip() {
        // 12.5 MB/s (100 Mbit/s) at 80 ms is a megabyte in flight.
        let window = Brutal::window_for(12_500_000, Duration::from_millis(80), 1.0);
        assert_eq!(window, 1_000_000);
    }

    #[test]
    fn loss_is_made_up_for_but_only_down_to_a_floor() {
        let rate = 1_000_000;
        let rtt = Duration::from_millis(100);
        let clean = Brutal::window_for(rate, rtt, 1.0);
        let lossy = Brutal::window_for(rate, rtt, 0.9);
        assert!(lossy > clean && lossy < clean * 12 / 10);
        // Past the floor the window stops growing.
        assert_eq!(
            Brutal::window_for(rate, rtt, 0.5),
            Brutal::window_for(rate, rtt, MIN_ACK_RATE)
        );
        // No RTT yet: a small fixed window rather than nonsense.
        assert_eq!(Brutal::window_for(rate, Duration::ZERO, 1.0), MIN_WINDOW);
    }

    #[test]
    fn the_ack_rate_is_believed_only_after_enough_traffic() {
        let mut ack = AckRate::new();
        let now = Instant::now();
        ack.lost(now, 1200);
        assert_eq!(ack.rate(), 1.0, "one lost packet says nothing");
        ack.acked(now, 100 * 1200);
        ack.lost(now, 25 * 1200);
        let rate = ack.rate();
        assert!((rate - 0.8).abs() < 0.01, "{rate}");
    }

    #[test]
    fn a_switchable_controller_is_its_inner_one_until_a_rate_is_set() {
        let (factory, handle) = SwitchableFactory::new(None);
        let now = Instant::now();
        let controller = factory.build(now, 1200);
        let inner_window = controller.window();
        assert_eq!(handle.rate(), 0);
        handle.set_rate(1_000_000);
        // No RTT sample yet, so Brutal's window is its floor, not the inner's.
        assert_eq!(controller.window(), MIN_WINDOW);
        handle.set_rate(0);
        assert_eq!(controller.window(), inner_window);
    }
}
