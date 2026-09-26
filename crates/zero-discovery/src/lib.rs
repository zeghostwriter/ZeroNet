//! `zero-discovery` — finding working servers from a mobile host.
//!
//! A censorship-circumvention client spends most of its first minute not
//! proxying anything but *looking*: fetching public feeds, sorting thousands
//! of share links, testing which of them still work on this network today.
//! This crate is that search, packaged for a host (the Android app, through
//! `zray-mobile`) that drives it with JSON and listens for JSON events:
//!
//! * [`link`] — pulls share links out of arbitrary text, keys them stably,
//!   summarises them ([`LinkInfo`]) and classifies them;
//! * [`order`] — interleaves candidates across server families;
//! * [`feed`] — fetches feeds with gzip and an ETag/Last-Modified disk cache;
//! * [`probe`] — the TCP and real (through-the-proxy) liveness tests;
//! * [`discover`], [`test_links`], [`scan`] — the three long-running jobs;
//! * [`events`] — batched event delivery to the host;
//! * [`config`] — turns the app's `BuildRequest` into a complete runtime
//!   configuration on top of `zero_config::IranPreset`.
//!
//! Every job takes a [`CancellationToken`](tokio_util::sync::CancellationToken)
//! and bounds its own concurrency; none of them polls or busy-waits.

pub mod config;
pub mod crowd;
pub mod crowd_client;
pub mod discover;
pub mod events;
pub mod feed;
pub mod json_subscription;
pub mod link;
pub mod order;
pub mod probe;
pub mod scan;
pub mod sign;
pub mod sources;
pub mod telegram;
pub mod test_links;

#[cfg(test)]
pub(crate) mod testing;

pub use config::{build_config, build_config_with_assets};
pub use discover::{discover, DiscoverRequest, EndReason};
pub use events::{batching_sink, EventCallback, EventSink};
pub use link::{link_key, parse_links, LinkClass, LinkInfo, ParseReport};
pub use scan::{scan, ScanRequest};
pub use test_links::{test_links, TestRequest};
pub use tokio_util::sync::CancellationToken;
