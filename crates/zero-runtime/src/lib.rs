//! `zero-runtime` — the composition root.
//!
//! Everything below this crate is independently testable and unaware of the
//! others. This is where a session becomes a stacked connection.

pub mod api;
mod dns_out;
pub mod outbound;
pub mod relay;
pub mod server;

pub use relay::{relay, RelayOutcome, Transferred};

/// Make freed connection buffers go back to the operating system.
///
/// Call once, first thing in `main`, before any thread exists. Every proxied
/// connection allocates a few
/// 16-64 KiB buffers. glibc raises its mmap threshold past sizes it has seen
/// freed, after which such buffers come from per-thread arenas that are
/// rarely returned: a burst of connections (a browser in TUN mode opens
/// hundreds) left the process holding its peak memory for good. Pinning the
/// threshold at 64 KiB keeps those buffers in their own mappings, released
/// the moment they are freed, for a few syscalls per connection.
pub fn tune_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt only adjusts allocator parameters; it is called before
    // any other thread exists.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, 64 * 1024);
        // One arena. With glibc's default (up to eight per core) every burst
        // of connections fragments whichever arenas tokio's workers happen to
        // land on, and memory climbed with each burst without bound: 300
        // connections through TUN, repeated six times, went 37 -> 136 MB.
        // With one arena the same load levels off at about 87 MB, for ~10 %
        // of aggregate throughput at 2.9 Gbit/s, far above any link a
        // proxy client sits behind.
        libc::mallopt(libc::M_ARENA_MAX, 1);
    }
}
pub use server::{asset_specs_for, asset_store_for, Server, ServerConfig};
