//! Warm carriers: one connection per outbound opened ahead of need.
//!
//! On a slow, high-latency path the handshakes, not the bandwidth, are what
//! a new connection costs. Measured from Center on 2026-09-28 through WARP
//! and then a Cloudflare Worker: 0.87 s to the first byte on a new
//! connection, 0.21 s on one already open — TCP through the tunnel, TLS and
//! the WebSocket upgrade are three round trips before anything useful.
//!
//! So after an outbound is used, the next connection for it is prepared in
//! the background — TCP, TLS and the transport upgrade, but not the protocol
//! header, which names a destination not yet known. The next session takes
//! it and writes only the header.
//!
//! Kept small on purpose, for phones and for what the network sees:
//!
//! * **demand-driven** — a carrier is prepared only after its outbound was
//!   used, one per use; an idle app opens nothing;
//! * **bounded** — at most one carrier per outbound and [`MAX_CARRIERS`] in
//!   all, each a few tens of kilobytes;
//! * **short-lived** — a carrier lives a random 15–25 s and is then closed,
//!   so nothing idles for long and there is no fixed rhythm to recognise;
//!   an idle TLS connection that closes after a while is ordinary browser
//!   behaviour;
//! * **never trusted blindly** — one that has closed, or predates a network
//!   change, is thrown away, and a warm carrier that fails when used falls
//!   back to an ordinary connection, so a stale carrier never costs a
//!   request.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, ReadBuf};
use zero_core::BoxStream;

/// Most warm carriers held at once, across all outbounds.
pub const MAX_CARRIERS: usize = 8;
const MIN_LIFETIME: Duration = Duration::from_secs(15);
const MAX_LIFETIME: Duration = Duration::from_secs(25);

/// Bumped on every network change: a carrier opened on the old network is
/// bound to an interface that may be gone.
static NETWORK_EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn network_changed() {
    NETWORK_EPOCH.fetch_add(1, Ordering::AcqRel);
}

struct Carrier {
    stream: BoxStream,
    until: Instant,
    epoch: u64,
}

#[derive(Default)]
struct Slot {
    ready: Option<Carrier>,
    filling: bool,
}

pub struct WarmPool {
    slots: StdMutex<HashMap<u64, Slot>>,
    /// The network epoch this pool checks carriers against: the process-wide
    /// one, or a private one in tests.
    epoch: &'static AtomicU64,
}

impl Default for WarmPool {
    fn default() -> Self {
        Self {
            slots: StdMutex::default(),
            epoch: &NETWORK_EPOCH,
        }
    }
}

/// The pool key of an outbound: its whole compiled form, so two outbounds
/// that differ in anything (address, SNI, fragmenting) never share a carrier.
pub fn key(outbound: &zero_config::Outbound) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{outbound:?}").hash(&mut hasher);
    hasher.finish()
}

impl WarmPool {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Slot>> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A live carrier for `key`, if one is ready.
    pub fn take(&self, key: u64) -> Option<BoxStream> {
        let mut carrier = self.lock().get_mut(&key)?.ready.take()?;
        let fresh =
            Instant::now() < carrier.until && carrier.epoch == self.epoch.load(Ordering::Acquire);
        (fresh && still_open(&mut carrier.stream)).then_some(carrier.stream)
    }

    /// Claim the right to prepare a carrier for `key`. False when one is
    /// ready or being prepared, or the pool is full.
    pub fn begin(&self, key: u64) -> bool {
        let mut slots = self.lock();
        let held = slots
            .values()
            .filter(|slot| slot.ready.is_some() || slot.filling)
            .count();
        let slot = slots.entry(key).or_default();
        if slot.ready.is_some() || slot.filling || held >= MAX_CARRIERS {
            return false;
        }
        slot.filling = true;
        true
    }

    /// Store a prepared carrier (or record that preparing it failed), and
    /// close it when its lifetime ends unless it was taken first.
    pub fn finish(self: &Arc<Self>, key: u64, stream: Option<BoxStream>) {
        let lifetime = MIN_LIFETIME + (MAX_LIFETIME - MIN_LIFETIME).mul_f64(rand::random::<f64>());
        let until = Instant::now() + lifetime;
        {
            let mut slots = self.lock();
            let slot = slots.entry(key).or_default();
            slot.filling = false;
            slot.ready = stream.map(|stream| Carrier {
                stream,
                until,
                epoch: self.epoch.load(Ordering::Acquire),
            });
            if slot.ready.is_none() {
                slots.remove(&key);
                return;
            }
        }
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            let mut slots = pool.lock();
            let expired = slots
                .get(&key)
                .and_then(|slot| slot.ready.as_ref())
                .is_some_and(|carrier| carrier.until == until);
            if expired {
                // Dropping the carrier closes it.
                slots.remove(&key);
            }
        });
    }

    /// Carriers held right now (ready or being prepared).
    pub fn held(&self) -> usize {
        self.lock()
            .values()
            .filter(|slot| slot.ready.is_some() || slot.filling)
            .count()
    }
}

/// Whether a carrier is still open, without waiting: a read that would block
/// means open and idle. End of stream, an error, or bytes nobody asked for
/// (the server has nothing to say before our request) mean it cannot be used.
fn still_open(stream: &mut BoxStream) -> bool {
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut byte = [0u8; 1];
    let mut buffer = ReadBuf::new(&mut byte);
    matches!(
        Pin::new(stream).poll_read(&mut context, &mut buffer),
        Poll::Pending
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A pool with its own network epoch, so tests running in parallel
    /// cannot retire each other's carriers.
    fn isolated() -> (Arc<WarmPool>, &'static AtomicU64) {
        let epoch: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));
        let pool = WarmPool {
            slots: StdMutex::default(),
            epoch,
        };
        (Arc::new(pool), epoch)
    }

    fn pair() -> (BoxStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1024);
        (zero_core::boxed(a), b)
    }

    #[tokio::test]
    async fn a_prepared_carrier_is_taken_once() {
        let (pool, _epoch) = isolated();
        assert!(pool.begin(1));
        assert!(!pool.begin(1), "one carrier per outbound");
        let (carrier, _peer) = pair();
        pool.finish(1, Some(carrier));
        assert!(pool.take(1).is_some());
        assert!(pool.take(1).is_none());
    }

    #[tokio::test]
    async fn a_closed_carrier_is_thrown_away() {
        let (pool, _epoch) = isolated();
        assert!(pool.begin(2));
        let (carrier, peer) = pair();
        pool.finish(2, Some(carrier));
        drop(peer);
        assert!(pool.take(2).is_none());
    }

    #[tokio::test]
    async fn unexpected_bytes_mean_unusable() {
        let (pool, _epoch) = isolated();
        assert!(pool.begin(3));
        let (carrier, mut peer) = pair();
        pool.finish(3, Some(carrier));
        peer.write_all(b"x").await.unwrap();
        assert!(pool.take(3).is_none());
    }

    #[tokio::test]
    async fn a_network_change_retires_every_carrier() {
        let (pool, epoch) = isolated();
        assert!(pool.begin(4));
        let (carrier, _peer) = pair();
        pool.finish(4, Some(carrier));
        epoch.fetch_add(1, Ordering::AcqRel);
        assert!(pool.take(4).is_none());
    }

    #[tokio::test]
    async fn the_pool_is_bounded() {
        let (pool, _epoch) = isolated();
        let mut peers = Vec::new();
        for key in 100..100 + MAX_CARRIERS as u64 {
            assert!(pool.begin(key));
            let (carrier, peer) = pair();
            peers.push(peer);
            pool.finish(key, Some(carrier));
        }
        assert!(!pool.begin(999), "no carrier beyond the cap");
        assert_eq!(pool.held(), MAX_CARRIERS);
    }

    #[tokio::test(start_paused = true)]
    async fn carriers_close_when_their_lifetime_ends() {
        let (pool, _epoch) = isolated();
        assert!(pool.begin(5));
        let (carrier, _peer) = pair();
        pool.finish(5, Some(carrier));
        tokio::time::sleep(MAX_LIFETIME + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(pool.held(), 0);
    }
}
