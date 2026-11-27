//! The multi-level send queue the stream layer drains onto the wire.
//!
//! This is a port of the Go `internal/mlq` `MultiLevelQueue[T]`. It is a set of
//! six FIFO levels, numbered 0 (highest priority) through 5 (lowest), plus a
//! map from a caller-chosen `u64` key to the queued item so existence checks
//! and removals are O(1). A bitmask records which levels are non-empty, so
//! finding the highest-priority non-empty level is a single trailing-zeros.
//!
//! What goes in and comes out: [`push`](MultiLevelQueue::push) files an item at
//! a level under a key, refusing a key that is already queued (that dedup is how
//! the enqueuer keeps two copies of the same packet off the wire).
//! [`pop`](MultiLevelQueue::pop) takes the front of the lowest-numbered
//! non-empty level.
//!
//! The invariant a newcomer must keep: this is **strict** priority with **no**
//! aging. A steady supply at a high level will starve every level beneath it —
//! that is intentional and the server depends on it (ACKs and setup must never
//! wait behind bulk data). Order inside a level is strict FIFO.
//!
//! Unlike the Go type this holds no lock of its own; the Go `sync.RWMutex` is
//! replaced by whatever lock the owning stream already holds, which avoids
//! locking twice on the hot path.

use std::collections::HashMap;

/// Number of priority levels. Levels are `0..LEVELS`; a priority at or beyond
/// this is folded to [`FALLBACK_PRIORITY`], matching the Go clamp.
pub const LEVELS: usize = 6;

/// Where an out-of-range priority lands (Go uses `3`, i.e. `Normal`).
pub const FALLBACK_PRIORITY: usize = 3;

/// One queued item: its dedup key, the payload, the level it sits in, and the
/// intrusive doubly-linked-list neighbours (indices into [`MultiLevelQueue::slots`]).
struct Node<T> {
    key: u64,
    item: T,
    priority: usize,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Head/tail/len bookkeeping for a single priority level's FIFO list.
#[derive(Default, Clone, Copy)]
struct Level {
    head: Option<usize>,
    tail: Option<usize>,
    len: usize,
}

/// A strict-priority multi-level FIFO with O(1) keyed removal.
///
/// `T` is the queued item (in the client, a transmit packet). Removal and
/// existence go through the `u64` key the caller supplies on [`push`]; the Go
/// code builds that key from the packet identity so the same logical packet
/// cannot be queued twice.
pub struct MultiLevelQueue<T> {
    levels: [Level; LEVELS],
    bitmask: u16,
    // Node arena. A `None` slot is free and its index lives in `free`.
    slots: Vec<Option<Node<T>>>,
    free: Vec<usize>,
    census: HashMap<u64, usize>,
}

impl<T> Default for MultiLevelQueue<T> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<T> MultiLevelQueue<T> {
    /// Build an empty queue, pre-sizing the key map for `initial_capacity`
    /// entries the way Go's `New` does.
    pub fn new(initial_capacity: usize) -> Self {
        MultiLevelQueue {
            levels: [Level::default(); LEVELS],
            bitmask: 0,
            slots: Vec::with_capacity(initial_capacity),
            free: Vec::new(),
            census: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Queue `item` at `priority` under `key`. Returns `false` without changing
    /// anything if `key` is already queued. A `priority >= LEVELS` is folded to
    /// [`FALLBACK_PRIORITY`].
    pub fn push(&mut self, priority: usize, key: u64, item: T) -> bool {
        if self.census.contains_key(&key) {
            return false;
        }
        let priority = if priority >= LEVELS {
            FALLBACK_PRIORITY
        } else {
            priority
        };

        let idx = self.alloc(Node {
            key,
            item,
            priority,
            prev: self.levels[priority].tail,
            next: None,
        });

        let level = &mut self.levels[priority];
        match level.tail {
            Some(tail) => self.slots[tail].as_mut().unwrap().next = Some(idx),
            None => level.head = Some(idx),
        }
        self.levels[priority].tail = Some(idx);
        self.levels[priority].len += 1;
        self.census.insert(key, idx);
        self.bitmask |= 1 << priority;
        true
    }

    /// Remove and return the front of the lowest-numbered non-empty level,
    /// along with that level number.
    pub fn pop(&mut self) -> Option<(T, usize)> {
        while self.bitmask != 0 {
            let priority = self.bitmask.trailing_zeros() as usize;
            match self.levels[priority].head {
                None => {
                    self.bitmask &= !(1 << priority);
                }
                Some(idx) => {
                    let node = self.unlink(idx);
                    return Some((node.item, priority));
                }
            }
        }
        None
    }

    /// Borrow the front item of the highest-priority non-empty level without
    /// removing it, along with its level.
    pub fn peek(&self) -> Option<(&T, usize)> {
        let mut mask = self.bitmask;
        while mask != 0 {
            let priority = mask.trailing_zeros() as usize;
            if let Some(idx) = self.levels[priority].head {
                return Some((&self.slots[idx].as_ref().unwrap().item, priority));
            }
            mask &= !(1 << priority);
        }
        None
    }

    /// Borrow a queued item by key.
    pub fn get(&self, key: u64) -> Option<&T> {
        let idx = *self.census.get(&key)?;
        Some(&self.slots[idx].as_ref().unwrap().item)
    }

    /// Remove and return a queued item by key, or `None` if it is not queued.
    pub fn remove_by_key(&mut self, key: u64) -> Option<T> {
        let idx = *self.census.get(&key)?;
        Some(self.unlink(idx).item)
    }

    /// Number of items currently at `priority` (0 if out of range).
    pub fn count(&self, priority: usize) -> usize {
        self.levels.get(priority).map_or(0, |l| l.len)
    }

    /// Total number of queued items.
    pub fn len(&self) -> usize {
        self.census.len()
    }

    /// Whether the queue holds no items.
    pub fn is_empty(&self) -> bool {
        self.census.is_empty()
    }

    /// The highest-priority (lowest-numbered) non-empty level, or `None` when
    /// the queue is empty. Go returns `-1` for empty; `None` is the Rust shape.
    pub fn highest_priority(&self) -> Option<usize> {
        if self.bitmask == 0 {
            None
        } else {
            Some(self.bitmask.trailing_zeros() as usize)
        }
    }

    /// Drain every item, lowest level first and FIFO within a level, handing
    /// each to `callback`. Leaves the queue empty. Mirrors Go `Clear`.
    pub fn clear(&mut self, mut callback: impl FnMut(T)) {
        for priority in 0..LEVELS {
            let mut cur = self.levels[priority].head;
            while let Some(idx) = cur {
                let node = self.slots[idx].take().unwrap();
                cur = node.next;
                callback(node.item);
            }
            self.levels[priority] = Level::default();
        }
        self.census.clear();
        self.free.clear();
        self.slots.clear();
        self.bitmask = 0;
    }

    /// If the front of exactly `priority` satisfies `predicate`, remove and
    /// return it; otherwise return `None` without touching the queue. Only the
    /// single front element of that level is tested, matching Go `PopIf`.
    pub fn pop_if(&mut self, priority: usize, predicate: impl Fn(&T) -> bool) -> Option<T> {
        if self.bitmask == 0 || priority >= LEVELS {
            return None;
        }
        if self.bitmask & (1 << priority) == 0 {
            return None;
        }
        let idx = match self.levels[priority].head {
            None => {
                self.bitmask &= !(1 << priority);
                return None;
            }
            Some(idx) => idx,
        };
        if !predicate(&self.slots[idx].as_ref().unwrap().item) {
            return None;
        }
        Some(self.unlink(idx).item)
    }

    /// Scan levels `0..=max_priority`, and within each scan every element front
    /// to back, removing and returning the first that satisfies `predicate`.
    /// Mirrors Go `PopAnyIf` (whole-level scan, not just the front).
    pub fn pop_any_if(&mut self, max_priority: usize, predicate: impl Fn(&T) -> bool) -> Option<T> {
        if self.bitmask == 0 {
            return None;
        }
        let mut mask = self.bitmask;
        while mask != 0 {
            let priority = mask.trailing_zeros() as usize;
            if priority > max_priority {
                break;
            }
            let mut cur = self.levels[priority].head;
            while let Some(idx) = cur {
                cur = self.slots[idx].as_ref().unwrap().next;
                if predicate(&self.slots[idx].as_ref().unwrap().item) {
                    return Some(self.unlink(idx).item);
                }
            }
            mask &= !(1 << priority);
        }
        None
    }

    /// Place a node in the arena, reusing a freed slot when one is available.
    fn alloc(&mut self, node: Node<T>) -> usize {
        if let Some(idx) = self.free.pop() {
            self.slots[idx] = Some(node);
            idx
        } else {
            self.slots.push(Some(node));
            self.slots.len() - 1
        }
    }

    /// Detach the node at `idx` from its level list and the key map, free its
    /// slot, clear the level's bitmask bit if it emptied, and return the node.
    fn unlink(&mut self, idx: usize) -> Node<T> {
        let node = self.slots[idx].take().expect("unlink of a free slot");
        let priority = node.priority;

        match node.prev {
            Some(prev) => self.slots[prev].as_mut().unwrap().next = node.next,
            None => self.levels[priority].head = node.next,
        }
        match node.next {
            Some(next) => self.slots[next].as_mut().unwrap().prev = node.prev,
            None => self.levels[priority].tail = node.prev,
        }

        self.levels[priority].len -= 1;
        self.census.remove(&node.key);
        self.free.push(idx);
        if self.levels[priority].len == 0 {
            self.bitmask &= !(1 << priority);
        }
        node
    }
}

#[cfg(test)]
mod tests;
