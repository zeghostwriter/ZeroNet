//! `zero-net` — sockets, candidate racing, and network observation.

pub mod clean_ip;
pub mod dial;
pub mod fetch;
pub mod socket;

pub use dial::{candidates, dial_tcp, order_candidates, Dialed, RacePolicy, SocketOptions};
pub use fetch::{fetch, fetch_with, post, post_with_headers, FetchError, FetchLimits, FetchOptions, Fetched, Validators};
pub use socket::prepare_listener;
