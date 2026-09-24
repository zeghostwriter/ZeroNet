//! A TUN descriptor handed over by the host application.
//!
//! Android and iOS do not let a process open a TUN device. `VpnService` and
//! `NEPacketTunnelProvider` create the interface themselves — with the
//! addresses, routes, MTU and DNS the user approved in a system dialog — and
//! give the application a descriptor. There is nothing for `TunDevice::open`
//! to open, and nothing for `configure_network` to configure; both would be
//! wrong even if they were possible.
//!
//! The descriptor arrives at a different time and by a different route from
//! everything else: it comes from a JNI or Swift callback at start-up, while
//! the rest of the configuration is JSON. Threading it through the config
//! model would mean inventing a way to spell "file descriptor 47" in a
//! document that is otherwise portable, serialisable and loggable — and a
//! descriptor is none of those things.
//!
//! So it is handed over separately, once, and *consumed* once. Ownership moves
//! to whoever takes it: the host must not close it afterwards, and a reload
//! must not adopt it twice, which is why taking it clears it.

use std::sync::Mutex;

/// A descriptor the host created and is giving away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InheritedTun {
    /// The open TUN descriptor. Ownership transfers on `take`.
    pub fd: i32,
    /// Platform framing in front of each packet: zero for Android's
    /// `VpnService`, four for iOS's `NEPacketTunnelProvider`.
    pub header_len: usize,
    /// The MTU the host configured on the interface. The proxy cannot query
    /// it — the interface is not in this process's control — and guessing it
    /// wrong either wastes payload or produces packets the host drops.
    pub mtu: usize,
}

static INHERITED: Mutex<Option<InheritedTun>> = Mutex::new(None);

/// Offer a descriptor for the runtime to adopt when it starts a TUN inbound.
///
/// Refused if one is already waiting, because a second descriptor would leak
/// the first: nothing would ever take it, and the host has already given up
/// ownership.
pub fn set(descriptor: InheritedTun) -> Result<(), &'static str> {
    if descriptor.fd < 0 {
        return Err("a TUN descriptor must be a valid file descriptor");
    }
    if descriptor.header_len > 4 {
        return Err("TUN header length must be 0..=4 bytes");
    }
    let mut slot = INHERITED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Err("a TUN descriptor is already waiting to be adopted");
    }
    *slot = Some(descriptor);
    Ok(())
}

/// Take the waiting descriptor, if any. Ownership moves to the caller.
pub fn take() -> Option<InheritedTun> {
    INHERITED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
}

/// Whether a descriptor is waiting. Does not consume it.
pub fn is_pending() -> bool {
    INHERITED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// Discard a descriptor that was offered but never adopted, without closing
/// it. Used when start-up fails and the host will close it itself.
pub fn clear() -> Option<InheritedTun> {
    take()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, because the slot is process-wide: parallel tests would take
    /// each other's descriptor.
    #[test]
    fn a_descriptor_is_offered_once_and_adopted_once() {
        assert!(!is_pending());
        assert!(take().is_none());

        let descriptor = InheritedTun {
            fd: 42,
            header_len: 0,
            mtu: 1500,
        };
        set(descriptor).expect("the first offer is accepted");
        assert!(is_pending());

        // A second offer would leak the first: the host has already given up
        // ownership of it and nothing would ever take it.
        assert!(set(InheritedTun {
            fd: 43,
            header_len: 4,
            mtu: 1500
        })
        .is_err());

        assert_eq!(take(), Some(descriptor));
        // Taken means taken. A reload that adopted it a second time would
        // hand the same descriptor to two owners, and the first close would
        // pull the device out from under the second.
        assert!(take().is_none());
        assert!(!is_pending());
    }

    #[test]
    fn an_invalid_descriptor_is_refused_at_the_boundary() {
        assert!(set(InheritedTun {
            fd: -1,
            header_len: 0,
            mtu: 1500
        })
        .is_err());
        // iOS uses four bytes of framing; anything beyond that is not a
        // platform this code knows, and adopting it would misparse every
        // packet rather than fail.
        assert!(set(InheritedTun {
            fd: 9,
            header_len: 8,
            mtu: 1500
        })
        .is_err());
        assert!(!is_pending());
    }
}
