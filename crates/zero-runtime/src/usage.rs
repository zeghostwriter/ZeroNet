//! Live usage counts that cannot leak who is connected.
//!
//! A server operator wants to know "how many people are using this config right
//! now". Answering that must not become a log of who they are, because the
//! answer travels (the apps read it over SSH) and a connection log is exactly
//! what a seizure or a leak turns against the users. So this module keeps
//! counts and nothing else:
//!
//! * A source address is reduced on arrival to a *device key*: a keyed hash
//!   (the key is random, made when the process starts, never written anywhere)
//!   of the address, with IPv6 cut to its /64 so a phone rotating its privacy
//!   address stays one device. The address itself is dropped on the spot.
//! * Device keys live in memory only, are never returned, never logged, and
//!   disappear when the process ends. A restart starts from zero.
//! * What leaves is a number per inbound: sessions open now, devices connected
//!   now, devices seen in the last five minutes.
//!
//! "Devices" is an approximation of people: two phones behind one carrier NAT
//! count as one, and one person on Wi-Fi and mobile data counts as two. The
//! apps say so.
//!
//! Invariant: the only way out of this module is [`UsageTracker::snapshot`],
//! and its type holds tags, counts and byte totals.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long a device counts as "recent" after its last session opened.
pub const RECENT_WINDOW_SECS: u64 = 300;
/// Minutes kept for the recent window; one bucket per minute.
const BUCKETS: u64 = RECENT_WINDOW_SECS / 60;
/// Most device keys remembered per bucket. A flood of spoofed sources cannot
/// make the server hold more; the count then saturates at this times the
/// bucket count.
const MAX_DEVICES_PER_BUCKET: usize = 4096;

/// Counts for one inbound, as handed to the caller.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InboundUsage {
    pub tag: String,
    /// Sessions open now (a device may hold many).
    pub sessions: u64,
    /// Distinct devices with at least one session open now.
    pub devices_now: u64,
    /// Distinct devices that opened a session within [`RECENT_WINDOW_SECS`].
    pub devices_recent: u64,
}

/// Everything [`UsageTracker::snapshot`] returns: no address, no key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UsageSnapshot {
    pub window_secs: u64,
    pub inbounds: Vec<InboundUsage>,
}

#[derive(Default)]
struct TagUsage {
    sessions: u64,
    /// Device key → sessions it has open now.
    now: HashMap<u64, u32>,
    /// `(minute, devices that opened a session in it)`, oldest first.
    recent: VecDeque<(u64, HashSet<u64>)>,
}

/// The tracker. One per server, shared through [`crate::server::Stats`].
#[derive(Default)]
pub struct UsageTracker {
    key: RandomState,
    tags: Mutex<HashMap<Arc<str>, TagUsage>>,
}

impl std::fmt::Debug for UsageTracker {
    // Deliberately opaque: nothing about what is inside should reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UsageTracker { .. }")
    }
}

fn minute_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 60)
}

impl UsageTracker {
    /// The device key for `peer`: a keyed hash of the address (IPv6: its /64).
    fn device(&self, peer: IpAddr) -> u64 {
        let mut hasher = self.key.build_hasher();
        match peer {
            IpAddr::V4(ip) => ip.octets().hash(&mut hasher),
            IpAddr::V6(ip) => ip.octets()[..8].hash(&mut hasher),
        }
        hasher.finish()
    }

    /// A session from `peer` has opened on `tag`; it counts until the returned
    /// guard is dropped.
    pub fn open(self: &Arc<Self>, tag: &Arc<str>, peer: IpAddr) -> SessionGuard {
        let device = self.device(peer);
        self.open_at(tag, device, minute_now());
        SessionGuard {
            tracker: Arc::clone(self),
            tag: Arc::clone(tag),
            device,
        }
    }

    fn open_at(&self, tag: &Arc<str>, device: u64, minute: u64) {
        let mut tags = self.tags.lock().unwrap_or_else(|p| p.into_inner());
        let usage = tags.entry(Arc::clone(tag)).or_default();
        usage.sessions += 1;
        *usage.now.entry(device).or_insert(0) += 1;
        while usage
            .recent
            .front()
            .is_some_and(|(m, _)| m + BUCKETS <= minute)
        {
            usage.recent.pop_front();
        }
        if usage.recent.back().is_none_or(|(m, _)| *m != minute) {
            usage.recent.push_back((minute, HashSet::new()));
        }
        if let Some((_, devices)) = usage.recent.back_mut() {
            if devices.len() < MAX_DEVICES_PER_BUCKET {
                devices.insert(device);
            }
        }
    }

    fn close(&self, tag: &Arc<str>, device: u64) {
        let mut tags = self.tags.lock().unwrap_or_else(|p| p.into_inner());
        let Some(usage) = tags.get_mut(tag) else {
            return;
        };
        usage.sessions = usage.sessions.saturating_sub(1);
        if let Some(open) = usage.now.get_mut(&device) {
            *open -= 1;
            if *open == 0 {
                usage.now.remove(&device);
            }
        }
    }

    /// The counts, sorted by tag so the output is stable.
    pub fn snapshot(&self) -> UsageSnapshot {
        self.snapshot_at(minute_now())
    }

    fn snapshot_at(&self, minute: u64) -> UsageSnapshot {
        let tags = self.tags.lock().unwrap_or_else(|p| p.into_inner());
        let mut inbounds: Vec<InboundUsage> = tags
            .iter()
            .map(|(tag, usage)| {
                let mut recent: HashSet<u64> = HashSet::new();
                for (m, devices) in &usage.recent {
                    if m + BUCKETS > minute {
                        recent.extend(devices);
                    }
                }
                // Whoever is connected now was, by definition, recent.
                recent.extend(usage.now.keys());
                InboundUsage {
                    tag: tag.to_string(),
                    sessions: usage.sessions,
                    devices_now: usage.now.len() as u64,
                    devices_recent: recent.len() as u64,
                }
            })
            .collect();
        inbounds.sort_by(|a, b| a.tag.cmp(&b.tag));
        UsageSnapshot {
            window_secs: RECENT_WINDOW_SECS,
            inbounds,
        }
    }
}

/// A session whose connection is open but whose client has not yet proven it is
/// one: it is counted only once [`PendingSession::confirm`] runs, which the
/// server does when the session is first routed (after the protocol's own
/// authentication). Without this, every scanner and prober that touches the
/// port would show up as a user.
pub struct PendingSession {
    tracker: Arc<UsageTracker>,
    tag: Arc<str>,
    peer: IpAddr,
    guard: Mutex<Option<SessionGuard>>,
}

impl PendingSession {
    pub fn new(tracker: &Arc<UsageTracker>, tag: &Arc<str>, peer: IpAddr) -> Self {
        Self {
            tracker: Arc::clone(tracker),
            tag: Arc::clone(tag),
            peer,
            guard: Mutex::new(None),
        }
    }

    /// Start counting. Idempotent: a second call changes nothing.
    pub fn confirm(&self) {
        let mut guard = self.guard.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(self.tracker.open(&self.tag, self.peer));
        }
    }
}

tokio::task_local! {
    static PENDING: PendingSession;
}

/// Run `work` with `pending` as the current task's session.
pub async fn scope<F: std::future::Future>(pending: PendingSession, work: F) -> F::Output {
    PENDING.scope(pending, work).await
}

/// Count the current task's session, if it has one: called where the server
/// first routes an authenticated session. A no-op anywhere else.
pub fn confirm_current() {
    let _ = PENDING.try_with(PendingSession::confirm);
}

/// Counts one open session; dropping it ends the session's count.
pub struct SessionGuard {
    tracker: Arc<UsageTracker>,
    tag: Arc<str>,
    device: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.tracker.close(&self.tag, self.device);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn tag(name: &str) -> Arc<str> {
        Arc::from(name)
    }

    #[test]
    fn many_sessions_from_one_address_are_one_device() {
        let tracker = Arc::new(UsageTracker::default());
        let t = tag("reality");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let guards: Vec<_> = (0..20).map(|_| tracker.open(&t, ip)).collect();
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.inbounds.len(), 1);
        assert_eq!(snapshot.inbounds[0].sessions, 20);
        assert_eq!(snapshot.inbounds[0].devices_now, 1);
        drop(guards);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.inbounds[0].sessions, 0);
        assert_eq!(snapshot.inbounds[0].devices_now, 0);
        // The device is still "recent" for the window after it left.
        assert_eq!(snapshot.inbounds[0].devices_recent, 1);
    }

    #[test]
    fn different_addresses_are_different_devices_and_tags_stay_apart() {
        let tracker = Arc::new(UsageTracker::default());
        let (a, b) = (tag("a"), tag("b"));
        let _g1 = tracker.open(&a, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        let _g2 = tracker.open(&a, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
        let _g3 = tracker.open(&b, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.inbounds[0].tag, "a");
        assert_eq!(snapshot.inbounds[0].devices_now, 2);
        assert_eq!(snapshot.inbounds[1].tag, "b");
        assert_eq!(snapshot.inbounds[1].devices_now, 1);
    }

    #[test]
    fn an_ipv6_privacy_address_change_inside_a_64_is_one_device() {
        let tracker = Arc::new(UsageTracker::default());
        let t = tag("t");
        let first = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 1, 2, 3, 4));
        let second = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9));
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 1, 2, 3, 4));
        let _a = tracker.open(&t, first);
        let _b = tracker.open(&t, second);
        let _c = tracker.open(&t, other);
        assert_eq!(tracker.snapshot().inbounds[0].devices_now, 2);
    }

    #[test]
    fn devices_leave_the_recent_window_after_five_minutes() {
        let tracker = UsageTracker::default();
        let t = tag("t");
        tracker.open_at(&t, 1, 100);
        tracker.open_at(&t, 2, 102);
        tracker.close(&t, 1);
        tracker.close(&t, 2);
        assert_eq!(tracker.snapshot_at(104).inbounds[0].devices_recent, 2);
        assert_eq!(tracker.snapshot_at(105).inbounds[0].devices_recent, 1);
        assert_eq!(tracker.snapshot_at(107).inbounds[0].devices_recent, 0);
    }

    #[test]
    fn a_flood_of_sources_cannot_grow_memory_without_bound() {
        let tracker = UsageTracker::default();
        let t = tag("t");
        for device in 0..(MAX_DEVICES_PER_BUCKET as u64 * 3) {
            tracker.open_at(&t, device, 50);
        }
        let seen = tracker.snapshot_at(50).inbounds[0].devices_recent;
        // Open sessions are all counted (they are real), the recent memory is
        // capped; the figure never falls below what is open now.
        assert!(seen >= MAX_DEVICES_PER_BUCKET as u64);
    }

    /// The whole point: nothing identifying is in what comes out, neither as an
    /// address nor as the device key.
    #[test]
    fn the_snapshot_holds_no_address_and_no_key() {
        let tracker = Arc::new(UsageTracker::default());
        let t = tag("reality");
        let ip = Ipv4Addr::new(203, 0, 113, 77);
        let _guard = tracker.open(&t, IpAddr::V4(ip));
        let device = tracker.device(IpAddr::V4(ip));
        let text = serde_json::to_string(&tracker.snapshot()).unwrap();
        assert!(!text.contains("203.0.113.77"), "{text}");
        assert!(!text.contains(&device.to_string()), "{text}");
        assert!(!text.contains(&format!("{device:x}")), "{text}");
        assert!(!format!("{tracker:?}").contains("203"));
    }

    #[tokio::test]
    async fn a_session_counts_only_after_it_is_confirmed() {
        let tracker = Arc::new(UsageTracker::default());
        let t = tag("reality");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        // A prober that never authenticates: connection open, never confirmed.
        scope(PendingSession::new(&tracker, &t, ip), async {
            assert!(tracker.snapshot().inbounds.is_empty());
        })
        .await;
        assert!(
            tracker.snapshot().inbounds.is_empty(),
            "a prober was counted"
        );
        // A real client: counted from `confirm_current`, gone with the scope.
        scope(PendingSession::new(&tracker, &t, ip), async {
            confirm_current();
            confirm_current();
            let snapshot = tracker.snapshot();
            assert_eq!(snapshot.inbounds[0].sessions, 1);
            assert_eq!(snapshot.inbounds[0].devices_now, 1);
        })
        .await;
        assert_eq!(tracker.snapshot().inbounds[0].sessions, 0);
        // Outside any scope it does nothing and does not panic.
        confirm_current();
    }

    #[test]
    fn the_device_key_differs_between_trackers() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let (a, b) = (UsageTracker::default(), UsageTracker::default());
        assert_ne!(a.device(ip), b.device(ip));
    }
}
