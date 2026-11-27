//! Automatic TCP segment size for the proxy's own outbound connections.
//!
//! The TUN device ends in a userspace TCP stack, so its MTU only governs the
//! hop between apps and the proxy; it never reaches the network. What does
//! reach the network is the proxy's own sockets to its servers, and on those
//! Iranian paths commonly carry less than 1500 bytes (PPPoE at 1492, mobile
//! GTP tunnels near 1400) while dropping the ICMP "fragmentation needed"
//! replies that path-MTU discovery depends on. The result is a black hole:
//! the SYN and the small ClientHello pass, the server's full-size certificate
//! flight never arrives, and the handshake times out.
//!
//! Setting `TCP_MAXSEG` before connect lowers the MSS we advertise, so the
//! server never sends a segment larger than we can take. That costs a few
//! bytes of header per packet — 40 in 1360, under 3% — and nothing else: no
//! probe traffic, no allocation, one `setsockopt` per connection.
//!
//! The policy is two steps and only goes down:
//!
//! * [`SAFE_MSS`] from the start, which fits a 1400-byte path;
//! * [`FLOOR_MSS`] after [`STALLS_TO_DESCEND`] handshake stalls in a row with
//!   no useful connection between them, which fits a 1280-byte path (the IPv6
//!   minimum, which no working network goes below).
//!
//! It returns to [`SAFE_MSS`] only when the network changes, so it cannot
//! flap on one network. The trade-off: stalls that come from SNI throttling
//! rather than the MTU also trip the descent, which then costs about 1% more
//! header overhead on that network for no gain. That is far cheaper than
//! the alternative of a connection that never completes.

use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// MSS for a 1400-byte path: 1400 minus 40 bytes of IPv4 and TCP header.
pub const SAFE_MSS: u16 = 1360;
/// MSS for a 1280-byte path under IPv6's 60 bytes of header, so one value
/// fits both families.
pub const FLOOR_MSS: u16 = 1220;
/// Consecutive handshake stalls, with no success between, before descending.
pub const STALLS_TO_DESCEND: u32 = 3;

static MSS: AtomicU16 = AtomicU16::new(SAFE_MSS);
static STALLS: AtomicU32 = AtomicU32::new(0);

/// The MSS new outbound connections advertise.
pub fn current() -> u16 {
    MSS.load(Ordering::Relaxed)
}

/// A connection reached the server but its handshake stalled before any
/// reply arrived. Returns `true` when this call lowered the MSS.
pub fn note_stall() -> bool {
    let stalls = STALLS.fetch_add(1, Ordering::AcqRel) + 1;
    stalls >= STALLS_TO_DESCEND
        && MSS
            .compare_exchange(SAFE_MSS, FLOOR_MSS, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
}

/// A connection made useful progress: the stalls so far were not a pattern.
pub fn note_progress() {
    STALLS.store(0, Ordering::Release);
}

/// The device moved to another network, whose path may be larger again.
pub fn network_changed() {
    STALLS.store(0, Ordering::Release);
    MSS.store(SAFE_MSS, Ordering::Release);
}

/// Apply the current MSS to a socket that has not connected yet. Best
/// effort: a platform that refuses the option keeps its own default, which
/// is exactly the behaviour before this existed.
#[cfg(unix)]
pub fn apply<S: std::os::fd::AsRawFd>(socket: &S) {
    let value = libc::c_int::from(current());
    // SAFETY: a valid descriptor and a correctly sized, initialised int.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Windows exposes `TCP_MAXSEG` as read-only, so there is nothing to set.
#[cfg(not(unix))]
pub fn apply<S>(_socket: &S) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state is process-wide; tests that change it take turns.
    static TEST_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        TEST_TURN.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn descends_once_after_consecutive_stalls_and_resets_on_network_change() {
        let _turn = turn();
        network_changed();
        assert_eq!(current(), SAFE_MSS);
        for _ in 1..STALLS_TO_DESCEND {
            assert!(!note_stall());
        }
        assert!(note_stall());
        assert_eq!(current(), FLOOR_MSS);
        // Further stalls do not report another descent.
        assert!(!note_stall());
        assert_eq!(current(), FLOOR_MSS);
        network_changed();
        assert_eq!(current(), SAFE_MSS);
    }

    #[test]
    fn progress_between_stalls_prevents_descent() {
        let _turn = turn();
        network_changed();
        for _ in 0..10 {
            assert!(!note_stall());
            note_progress();
        }
        assert_eq!(current(), SAFE_MSS);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn a_connected_socket_advertises_the_clamped_mss() {
        use std::os::fd::AsRawFd;
        // No turn needed: the MSS is SAFE_MSS or lower whatever other tests do.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        apply(&socket);
        let (stream, _) = tokio::join!(socket.connect(address), listener.accept());
        let stream = stream.unwrap();
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid descriptor and output buffer.
        let got = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(got, 0);
        assert!(value > 0 && value <= i32::from(SAFE_MSS), "mss {value}");
    }
}
