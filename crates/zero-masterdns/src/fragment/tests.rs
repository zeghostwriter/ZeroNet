//! Tests for the fragment reassembly store, mirroring the Go
//! `fragmentstore` cases and adding a few multi-chunk and purge checks.

use super::{Collect, FragmentStore};
use std::time::Duration;
use std::time::Instant;

fn base() -> Instant {
    Instant::now()
}

const RET: Duration = Duration::from_secs(300);

#[test]
fn single_fragment_completes_once_then_is_a_duplicate() {
    let mut store = FragmentStore::<&str>::new(4);
    let now = base();

    let first = store.collect("req", b"hello", 0, 1, now, RET);
    assert_eq!(first, Collect::Ready(b"hello".to_vec()));

    let again = store.collect("req", b"hello", 0, 1, now + Duration::from_secs(1), RET);
    assert_eq!(again, Collect::Duplicate);
}

#[test]
fn single_fragment_zero_retention_is_pure_passthrough() {
    let mut store = FragmentStore::<&str>::new(4);
    let now = base();
    // No retention => no dedup state, so the same key keeps passing through.
    assert_eq!(
        store.collect("x", b"a", 0, 1, now, Duration::ZERO),
        Collect::Ready(b"a".to_vec())
    );
    assert_eq!(
        store.collect("x", b"b", 0, 1, now, Duration::ZERO),
        Collect::Ready(b"b".to_vec())
    );
}

#[test]
fn multi_fragment_assembles_in_index_order() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    // Deliver out of order; the result must still be chunk0||chunk1||chunk2.
    assert_eq!(store.collect(7, b"world", 2, 3, now, RET), Collect::Pending);
    assert_eq!(store.collect(7, b"hello", 0, 3, now, RET), Collect::Pending);
    assert_eq!(
        store.collect(7, b" cruel ", 1, 3, now, RET),
        Collect::Ready(b"hello cruel world".to_vec())
    );
    // A late duplicate of the whole message is recognised.
    assert_eq!(
        store.collect(7, b"hello", 0, 3, now, RET),
        Collect::Duplicate
    );
}

#[test]
fn re_sending_same_fragment_does_not_double_count() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    assert_eq!(store.collect(1, b"aa", 0, 2, now, RET), Collect::Pending);
    // Same index again: overwrites, count stays 1, still not complete.
    assert_eq!(store.collect(1, b"AA", 0, 2, now, RET), Collect::Pending);
    assert_eq!(
        store.collect(1, b"bb", 1, 2, now, RET),
        Collect::Ready(b"AAbb".to_vec())
    );
}

#[test]
fn out_of_range_fragment_id_is_pending() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    // fragment_id == total is out of range (valid ids are 0..total).
    assert_eq!(store.collect(1, b"x", 2, 2, now, RET), Collect::Pending);
    assert!(store.items.is_empty());
}

#[test]
fn changing_total_resets_the_entry() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    assert_eq!(store.collect(1, b"a", 0, 3, now, RET), Collect::Pending);
    // A chunk that claims a different total starts a fresh entry of that size.
    assert_eq!(store.collect(1, b"a", 0, 2, now, RET), Collect::Pending);
    assert_eq!(
        store.collect(1, b"b", 1, 2, now, RET),
        Collect::Ready(b"ab".to_vec())
    );
}

#[test]
fn remove_if_clears_items_and_completed() {
    let mut store = FragmentStore::<i32>::new(4);
    let now = base();
    assert_eq!(store.collect(1, b"a", 0, 2, now, RET), Collect::Pending);
    assert_eq!(
        store.collect(2, b"b", 0, 1, now, RET),
        Collect::Ready(b"b".to_vec())
    );

    store.remove_if(|&k| k == 1 || k == 2);

    // The removed incomplete key behaves like a brand-new one.
    assert_eq!(
        store.collect(1, b"c", 1, 2, now + Duration::from_secs(1), RET),
        Collect::Pending
    );
    // The removed completed key accepts new data instead of deduplicating.
    assert_eq!(
        store.collect(2, b"d", 0, 1, now + Duration::from_secs(1), RET),
        Collect::Ready(b"d".to_vec())
    );
}

#[test]
fn stale_partials_are_purged_after_retention() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    assert_eq!(store.collect(1, b"a", 0, 2, now, RET), Collect::Pending);
    // Well past retention; the amortised purge inside collect drops the stale
    // partial, so the second fragment can no longer complete the old message.
    let later = now + RET + Duration::from_secs(2);
    assert_eq!(store.collect(1, b"b", 1, 2, later, RET), Collect::Pending);
    // Only the newly-stored fragment 1 remains, not a completed message.
    let entry = store.items.get(&1).unwrap();
    assert_eq!(entry.count, 1);
}

#[test]
fn remove_forgets_a_single_key() {
    let mut store = FragmentStore::<u64>::new(4);
    let now = base();
    store.collect(1, b"a", 0, 2, now, RET);
    store.remove(&1);
    assert!(store.items.is_empty());
}
