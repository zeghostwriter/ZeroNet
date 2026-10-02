//! A counting global allocator, so a benchmark can state how many allocations
//! and how many bytes a code path costs instead of asserting it.
//!
//! Counts are exact and deterministic, which is the point: a timing number on
//! a shared runner is a distribution, while an allocation count is a fact. The
//! throughput numbers elsewhere in this crate are reported next to these, but
//! the allocation counts are what the gate is written against.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Set while the benchmark is measuring. Counting is off otherwise, so the
/// harness's own bookkeeping never lands in a measurement.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
/// Allocations that were zero-filled by the allocator. `vec![0u8; n]` goes
/// through `alloc_zeroed`, so this counts the zero-fill a path asked for and
/// then had to overwrite. It is counted apart from `allocs` because a
/// zero-filled allocation costs a memset the caller did not need, and an
/// allocation count alone cannot see that.
static ZEROED: AtomicUsize = AtomicUsize::new(0);

pub struct Counting;

#[inline]
fn tally_add(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

#[inline]
fn tally_zeroed(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ZEROED.fetch_add(1, Ordering::Relaxed);
        tally_add(size);
    }
}

#[inline]
fn tally_realloc() {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        REALLOCS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally_add(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        tally_zeroed(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        tally_realloc();
        if ACTIVE.load(Ordering::Relaxed) != 0 {
            BYTES.fetch_add(new_size.saturating_sub(layout.size()), Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// What a measured region cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Number of distinct allocations.
    pub allocs: usize,
    /// Number of `realloc` calls, counted separately because they are a
    /// copy-and-grow rather than a fresh allocation.
    pub reallocs: usize,
    /// Total bytes requested across those allocations.
    pub bytes: usize,
    /// How many of `allocs` were zero-filled by the allocator. A `vec![0u8; n]`
    /// whose bytes are then overwritten costs a memset that the allocation
    /// count alone cannot see, so it is reported on its own.
    pub zeroed: usize,
}

impl Counts {
    pub fn allocs_per_iter(&self, iters: usize) -> f64 {
        self.allocs as f64 / iters as f64
    }

    pub fn bytes_per_iter(&self, iters: usize) -> f64 {
        self.bytes as f64 / iters as f64
    }

    pub fn zeroed_per_iter(&self, iters: usize) -> f64 {
        self.zeroed as f64 / iters as f64
    }
}

/// Count everything allocated while `body` is driven to completion.
///
/// The measured code is `async`, and an await may suspend, so the counter is
/// held across the whole future. Nothing else may allocate on this task while
/// it is held, which is why the benchmark drives one future at a time and
/// never spawns a measuring task.
pub async fn measure_async<F, R>(body: F) -> (R, Counts)
where
    F: std::future::Future<Output = R>,
{
    assert_eq!(
        ACTIVE.load(Ordering::Relaxed),
        0,
        "allocation counts cannot be nested"
    );
    ACTIVE.store(1, Ordering::Relaxed);
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    REALLOCS.store(0, Ordering::Relaxed);
    ZEROED.store(0, Ordering::Relaxed);
    let out = body.await;
    ACTIVE.store(0, Ordering::Relaxed);
    let counts = Counts {
        allocs: ALLOCS.load(Ordering::Relaxed),
        reallocs: REALLOCS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        zeroed: ZEROED.load(Ordering::Relaxed),
    };
    (out, counts)
}
