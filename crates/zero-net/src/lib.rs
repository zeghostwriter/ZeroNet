//! `zero-net` — sockets, candidate racing, and network observation.

pub mod clean_ip;
pub mod dial;
pub mod fetch;
pub mod socket;
pub mod tls_check;

pub use dial::{candidates, dial_tcp, order_candidates, Dialed, RacePolicy, SocketOptions};
pub use fetch::{
    fetch, fetch_with, post, post_over, post_with_headers, send_with_headers, FetchError,
    FetchLimits, FetchOptions, Fetched, Validators,
};
pub use socket::prepare_listener;
pub use tls_check::{verify_tls, verify_tls_with};
