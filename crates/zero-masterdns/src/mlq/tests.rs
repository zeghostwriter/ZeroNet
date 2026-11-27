//! Behaviour tests for the multi-level queue, mirroring the Go `mlq_test.go`
//! cases one for one so the Rust port keeps the same priority, FIFO, dedup and
//! removal semantics.

use super::MultiLevelQueue;

#[derive(Debug, PartialEq, Eq)]
struct Item {
    key: u64,
    value: &'static str,
}

fn item(key: u64, value: &'static str) -> Item {
    Item { key, value }
}

#[test]
fn push_pop_respects_priority_and_fifo() {
    let mut q = MultiLevelQueue::new(8);
    assert!(q.push(3, 1, item(1, "p3-a")));
    assert!(q.push(1, 2, item(2, "p1-a")));
    assert!(q.push(1, 3, item(3, "p1-b")));
    assert!(q.push(0, 4, item(4, "p0-a")));

    let (it, prio) = q.pop().unwrap();
    assert_eq!((prio, it.value), (0, "p0-a"));
    let (it, prio) = q.pop().unwrap();
    assert_eq!((prio, it.value), (1, "p1-a"));
    let (it, prio) = q.pop().unwrap();
    assert_eq!((prio, it.value), (1, "p1-b"));
    let (it, prio) = q.pop().unwrap();
    assert_eq!((prio, it.value), (3, "p3-a"));
    assert!(q.pop().is_none());
}

#[test]
fn rejects_duplicate_keys() {
    let mut q = MultiLevelQueue::new(4);
    assert!(q.push(2, 10, item(10, "first")));
    assert!(!q.push(2, 10, item(10, "dup")));
    assert_eq!(q.len(), 1);
    // The original item, not the duplicate, is what stays queued.
    assert_eq!(q.get(10).unwrap().value, "first");
}

#[test]
fn out_of_range_priority_folds_to_normal() {
    let mut q = MultiLevelQueue::new(4);
    assert!(q.push(99, 1, item(1, "folded")));
    assert_eq!(q.count(3), 1);
    assert_eq!(q.highest_priority(), Some(3));
}

#[test]
fn pop_if_only_consumes_matching_head() {
    let mut q = MultiLevelQueue::new(4);
    q.push(1, 1, item(1, "head"));
    q.push(1, 2, item(2, "next"));

    assert!(q.pop_if(1, |it| it.value == "nope").is_none());
    let got = q.pop_if(1, |it| it.value == "head").unwrap();
    assert_eq!(got.value, "head");

    let (it, _) = q.pop().unwrap();
    assert_eq!(it.value, "next");
}

#[test]
fn pop_any_if_finds_highest_priority_match() {
    let mut q = MultiLevelQueue::new(8);
    q.push(0, 1, item(1, "p0-nomatch"));
    q.push(1, 2, item(2, "p1-match"));
    q.push(2, 3, item(3, "p2-match"));

    let got = q
        .pop_any_if(5, |it| it.value == "p1-match" || it.value == "p2-match")
        .unwrap();
    assert_eq!(got.value, "p1-match");
    assert_eq!(q.len(), 2);
}

#[test]
fn pop_any_if_scans_whole_level_not_just_front() {
    let mut q = MultiLevelQueue::new(8);
    q.push(2, 1, item(1, "front"));
    q.push(2, 2, item(2, "middle"));
    q.push(2, 3, item(3, "back"));

    // The match is the third element of the single non-empty level.
    let got = q.pop_any_if(5, |it| it.value == "back").unwrap();
    assert_eq!(got.value, "back");
    // Front and middle keep their order.
    assert_eq!(q.pop().unwrap().0.value, "front");
    assert_eq!(q.pop().unwrap().0.value, "middle");
}

#[test]
fn pop_any_if_respects_max_priority_ceiling() {
    let mut q = MultiLevelQueue::new(8);
    q.push(4, 1, item(1, "low"));
    // Only levels 0..=2 are scanned; the level-4 match is out of reach.
    assert!(q.pop_any_if(2, |it| it.value == "low").is_none());
    assert_eq!(q.len(), 1);
}

#[test]
fn clear_invokes_callback_and_resets_state() {
    let mut q = MultiLevelQueue::new(4);
    q.push(0, 1, item(1, "a"));
    q.push(2, 2, item(2, "b"));

    let mut seen = Vec::new();
    q.clear(|it| seen.push(it.value));
    assert_eq!(seen, ["a", "b"]);
    assert_eq!(q.len(), 0);
    assert_eq!(q.highest_priority(), None);
    assert!(q.pop().is_none());
}

#[test]
fn peek_returns_head_without_removing() {
    let mut q = MultiLevelQueue::new(4);
    q.push(2, 1, item(1, "later"));
    q.push(1, 2, item(2, "first"));

    let (it, prio) = q.peek().unwrap();
    assert_eq!((prio, it.value), (1, "first"));
    assert_eq!(q.len(), 2);

    let (it, prio) = q.pop().unwrap();
    assert_eq!((prio, it.value), (1, "first"));
}

#[test]
fn remove_by_key_removes_queued_item() {
    let mut q = MultiLevelQueue::new(8);
    q.push(4, 10, item(10, "data"));
    q.push(2, 20, item(20, "other"));

    let got = q.remove_by_key(10).unwrap();
    assert_eq!(got.value, "data");
    assert_eq!(q.len(), 1);
    assert!(q.get(10).is_none());
    assert!(q.remove_by_key(10).is_none());
}

#[test]
fn len_tracks_all_mutations() {
    let mut q = MultiLevelQueue::new(8);
    assert_eq!(q.len(), 0);

    assert!(q.push(1, 1, item(1, "a")));
    assert!(q.push(2, 2, item(2, "b")));
    assert_eq!(q.len(), 2);

    assert!(q.remove_by_key(2).is_some());
    assert_eq!(q.len(), 1);

    assert!(q.pop_if(1, |it| it.key == 1).is_some());
    assert_eq!(q.len(), 0);

    assert!(q.push(0, 3, item(3, "c")));
    assert!(q.push(1, 4, item(4, "d")));
    assert_eq!(q.len(), 2);

    assert!(q.pop_any_if(5, |it| it.key == 4).is_some());
    assert_eq!(q.len(), 1);

    q.clear(|_| {});
    assert_eq!(q.len(), 0);
}

#[test]
fn arena_slots_are_recycled_across_churn() {
    // Push and pop many times; the arena must not grow without bound, which
    // confirms freed slots are reused rather than leaked.
    let mut q = MultiLevelQueue::new(2);
    for round in 0..1000u64 {
        assert!(q.push(3, round, item(round, "x")));
        let (it, _) = q.pop().unwrap();
        assert_eq!(it.key, round);
        assert!(q.is_empty());
    }
    // A single live item at a time means at most one slot ever in use.
    assert!(q.slots.len() <= 1);
}
