//! Reassembly store for fragmented tunnel payloads.
//!
//! A few packet types (stream setup, a SOCKS target, a tunneled DNS message)
//! can be split across several DNS exchanges when they do not fit one query.
//! This store collects those chunks by a caller-chosen key until the whole set
//! has arrived, then hands back the concatenation. It is a direct port of the
//! Go `internal/fragmentstore`.
//!
//! How it works: [`FragmentStore::collect`] takes one chunk at a time, tagged
//! with its index and the total count. A single-chunk message (`total <= 1`) is
//! returned straight back. For a real split, chunks accumulate under the key
//! until every index `0..total` is present, at which point the assembled bytes
//! come out exactly once. After a message completes it is remembered for
//! `retention` so a late duplicate is recognised and dropped rather than
//! reassembled a second time. Stale partial and completed entries are swept
//! lazily, at most once a second, from inside `collect`.
//!
//! The invariant: a given key yields its assembled payload at most once within
//! a retention window; repeats come back as [`Collect::Duplicate`]. A newcomer
//! should note the amortised purge — the store does no background work, so a
//! key that never completes is only reclaimed by a later `collect`, `purge`,
//! or `remove`.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Outcome of feeding one chunk to [`FragmentStore::collect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collect {
    /// The message is complete; here are its assembled bytes (handed out once).
    Ready(Vec<u8>),
    /// More chunks are still needed (or the chunk was out of range).
    Pending,
    /// This key already completed within the retention window; chunk ignored.
    Duplicate,
}

/// One in-progress reassembly: when it started, how many chunks it expects, the
/// chunk slots, and how many distinct slots are filled.
struct Entry {
    created_at: Instant,
    total_fragments: u8,
    chunks: Vec<Option<Vec<u8>>>,
    count: u8,
}

/// A keyed fragment reassembly store. `K` identifies a message (the client keys
/// it by session id and sequence number).
pub struct FragmentStore<K: Eq + Hash> {
    items: HashMap<K, Entry>,
    completed: HashMap<K, Instant>,
    last_purge: Option<Instant>,
}

impl<K: Eq + Hash + Clone> FragmentStore<K> {
    /// Build an empty store, pre-sizing the maps for `capacity` keys (clamped
    /// up to 16 the way Go does for a zero or negative request).
    pub fn new(capacity: usize) -> Self {
        let capacity = if capacity < 1 { 16 } else { capacity };
        FragmentStore {
            items: HashMap::with_capacity(capacity),
            completed: HashMap::with_capacity(capacity),
            last_purge: None,
        }
    }

    /// Feed one chunk. `fragment_id` is this chunk's index and
    /// `total_fragments` the number expected; `now` drives expiry and
    /// `retention` is how long a completed key is remembered.
    ///
    /// A `total_fragments <= 1` message is returned immediately. With a zero
    /// retention it is a pure pass-through with no bookkeeping (the single-chunk
    /// fast path the dispatcher leans on); otherwise it is deduplicated like any
    /// other completed message.
    pub fn collect(
        &mut self,
        key: K,
        payload: &[u8],
        fragment_id: u8,
        total_fragments: u8,
        now: Instant,
        retention: Duration,
    ) -> Collect {
        if total_fragments <= 1 {
            if retention.is_zero() {
                return Collect::Ready(payload.to_vec());
            }
            self.maybe_purge(now, retention);
            if self.is_recent_completed(&key, now) {
                return Collect::Duplicate;
            }
            self.items.remove(&key);
            self.completed.insert(key, now + retention);
            return Collect::Ready(payload.to_vec());
        }

        if fragment_id >= total_fragments {
            return Collect::Pending;
        }

        self.maybe_purge(now, retention);
        if self.is_recent_completed(&key, now) {
            return Collect::Duplicate;
        }

        let total = total_fragments as usize;
        let entry = match self.items.get_mut(&key) {
            Some(e) if e.total_fragments == total_fragments => e,
            _ => {
                self.items.insert(
                    key.clone(),
                    Entry {
                        created_at: now,
                        total_fragments,
                        chunks: (0..total).map(|_| None).collect(),
                        count: 0,
                    },
                );
                self.items.get_mut(&key).unwrap()
            }
        };

        let slot = &mut entry.chunks[fragment_id as usize];
        if slot.is_none() {
            entry.count += 1;
        }
        *slot = Some(payload.to_vec());

        if entry.count < total_fragments {
            return Collect::Pending;
        }

        // All slots must be present before assembling; a defensive re-check
        // mirroring Go in case a count ever disagrees with the slots.
        let total_size: usize = match entry
            .chunks
            .iter()
            .map(|c| c.as_ref().map(Vec::len))
            .sum::<Option<usize>>()
        {
            // The sum is None if any chunk slot is still empty.
            Some(size) => size,
            None => return Collect::Pending,
        };

        let mut assembled = Vec::with_capacity(total_size);
        for chunk in &entry.chunks {
            assembled.extend_from_slice(chunk.as_ref().unwrap());
        }

        self.items.remove(&key);
        if retention.is_zero() {
            self.completed.remove(&key);
        } else {
            self.completed.insert(key, now + retention);
        }
        Collect::Ready(assembled)
    }

    /// Drop stale partial and completed entries. Normally called for you by
    /// [`collect`](Self::collect); exposed for the periodic sweeper.
    pub fn purge(&mut self, now: Instant, retention: Duration) {
        self.purge_locked(now, retention);
    }

    /// Forget everything about one key.
    pub fn remove(&mut self, key: &K) {
        self.items.remove(key);
        self.completed.remove(key);
    }

    /// Forget every key the predicate accepts (used to tear down a stream).
    pub fn remove_if(&mut self, mut matches: impl FnMut(&K) -> bool) {
        self.items.retain(|k, _| !matches(k));
        self.completed.retain(|k, _| !matches(k));
    }

    /// Run the amortised purge at most once per second.
    fn maybe_purge(&mut self, now: Instant, retention: Duration) {
        let due = match self.last_purge {
            None => true,
            Some(last) => now.duration_since(last) >= Duration::from_secs(1),
        };
        if due {
            self.purge_locked(now, retention);
            self.last_purge = Some(now);
        }
    }

    /// Whether `key` completed recently enough to still deduplicate.
    fn is_recent_completed(&self, key: &K, now: Instant) -> bool {
        matches!(self.completed.get(key), Some(&expires_at) if now < expires_at)
    }

    fn purge_locked(&mut self, now: Instant, retention: Duration) {
        if retention.is_zero() {
            self.items.clear();
            self.completed.clear();
            return;
        }
        // Keep an item only while it is younger than the retention window.
        self.items
            .retain(|_, entry| now.saturating_duration_since(entry.created_at) < retention);
        // Keep a completed marker only until its stored expiry.
        self.completed.retain(|_, &mut expires_at| now < expires_at);
    }
}

#[cfg(test)]
mod tests;
