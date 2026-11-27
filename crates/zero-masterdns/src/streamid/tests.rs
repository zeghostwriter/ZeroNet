//! Tests for the circular stream-id allocator. Occupancy is supplied as a
//! closure over a `HashSet`, exactly how the live layer would back it with the
//! real stream table, and the cases check the forward walk, the `65535 -> 1`
//! wrap that skips id 0, the "all taken" result, and that the cursor only moves
//! on success — against the Go `get_new_stream_id` behaviour.

use super::*;

use std::collections::HashSet;

/// Build an occupancy closure over a fixed set of ids.
fn occupied_set(ids: &[u16]) -> HashSet<u16> {
    ids.iter().copied().collect()
}

#[test]
fn fresh_allocator_starts_at_one() {
    let mut a = StreamIdAllocator::new();
    let taken = occupied_set(&[]);
    assert_eq!(a.allocate(&|id| taken.contains(&id)), Some(1));
    assert_eq!(a.last(), 1);
}

#[test]
fn allocation_walks_forward() {
    let mut a = StreamIdAllocator::new();
    let taken = occupied_set(&[]);
    let occ = |id: u16| taken.contains(&id);
    assert_eq!(a.allocate(&occ), Some(1));
    assert_eq!(a.allocate(&occ), Some(2));
    assert_eq!(a.allocate(&occ), Some(3));
}

#[test]
fn allocation_skips_occupied_ids() {
    let mut a = StreamIdAllocator::new();
    // 1, 2, 3 are busy; the first free id at or after 1 is 4.
    let taken = occupied_set(&[1, 2, 3]);
    assert_eq!(a.allocate(&|id| taken.contains(&id)), Some(4));
    assert_eq!(a.last(), 4);
}

#[test]
fn allocation_resumes_from_the_cursor() {
    let mut a = StreamIdAllocator::new();
    let taken = occupied_set(&[]);
    let occ = |id: u16| taken.contains(&id);
    assert_eq!(a.allocate(&occ), Some(1));
    assert_eq!(a.allocate(&occ), Some(2));
    // A fresh search does not go back to 1 even though it is now free in this
    // (stateless) occupancy set — the cursor carries forward.
    assert_eq!(a.allocate(&occ), Some(3));
}

#[test]
fn allocation_wraps_past_the_top_and_skips_zero() {
    let mut a = StreamIdAllocator::new();
    // Pretend the last id handed out was the maximum.
    a.last = 65535;
    // Nothing is occupied, so the search starts at 65535+1 -> 0 -> forced to 1.
    let taken = occupied_set(&[]);
    assert_eq!(a.allocate(&|id| taken.contains(&id)), Some(1));
    assert_eq!(a.last(), 1);
}

#[test]
fn allocation_wraps_to_find_a_low_free_id() {
    let mut a = StreamIdAllocator::new();
    a.last = 65534;
    // 65535 is busy; the only free id is 7, which the search reaches only after
    // wrapping 65535 -> 1 and walking up.
    let mut busy: HashSet<u16> = (1..=65535).collect();
    busy.remove(&7);
    assert_eq!(a.allocate(&|id| busy.contains(&id)), Some(7));
    assert_eq!(a.last(), 7);
}

#[test]
fn full_table_returns_none_and_keeps_the_cursor() {
    let mut a = StreamIdAllocator::new();
    a.last = 40;
    // Every usable id is taken.
    let busy: HashSet<u16> = (1..=65535).collect();
    assert_eq!(a.allocate(&|id| busy.contains(&id)), None);
    // The cursor did not move on failure.
    assert_eq!(a.last(), 40);
}

#[test]
fn id_zero_is_never_handed_out() {
    let mut a = StreamIdAllocator::new();
    // Only id 0 is "free" (and it is reserved), everything else taken.
    let busy: HashSet<u16> = (1..=65535).collect();
    assert_eq!(a.allocate(&|id| busy.contains(&id)), None);
}
