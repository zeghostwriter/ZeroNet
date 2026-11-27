//! The circular stream-id allocator, as a pure (sans-IO) state machine.
//!
//! Every local connection the client accepts (a SOCKS or TCP connection) needs
//! a stream id to carry it over the tunnel. Ids run `1..=65535` — id `0` is the
//! permanent virtual control/ping stream and is never handed out here. The
//! allocator walks forward from the last id it gave, wrapping past the top, and
//! returns the first id that is not already in use. Walking forward (rather than
//! always starting at `1`) keeps a just-freed id from being reused immediately,
//! which would risk colliding with packets still in flight for the old stream.
//!
//! This is the deterministic half: it owns only the "last id handed out" cursor
//! and asks the caller whether a given id is currently occupied. It never
//! touches the stream table itself, so it is trivially testable and the live
//! layer keeps the lock around the real table.
//!
//! # The one rule to remember (the invariant)
//!
//! The cursor only moves when an id is successfully handed out. A failed
//! allocation (every id taken) leaves the cursor where it was, so the next
//! attempt resumes from the same place rather than restarting at `1`.
//!
//! Ported from the Go client's `get_new_stream_id` in
//! `internal/client/stream_client.go` at the pinned release
//! `v2026.06.13.234407-7de2476`, matching its wrap and termination exactly.

#[cfg(test)]
mod tests;

/// Hands out stream ids in a forward-walking circle over `1..=65535`. Create
/// one with [`new`](Self::new) when the session starts; call
/// [`allocate`](Self::allocate) for each new local connection.
#[derive(Debug, Clone, Default)]
pub struct StreamIdAllocator {
    /// The last id successfully handed out (0 before the first one, which is
    /// why the first search starts at 1).
    last: u16,
}

impl StreamIdAllocator {
    /// A fresh allocator whose first handed-out id will be the first free id at
    /// or after `1`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Find and reserve the next free stream id, asking `occupied` whether each
    /// candidate id is already in use. Returns `None` only when all 65535 ids
    /// are taken (which the client treats as "no capacity"), in which case the
    /// cursor is left unchanged.
    ///
    /// The search starts one past the last id handed out, wraps `65535 -> 1`
    /// (skipping `0`), and stops once it has looped all the way back to where it
    /// started. On success the cursor advances to the id returned.
    ///
    /// `occupied` is taken as `&dyn Fn` rather than a generic so this compiles
    /// to one copy — allocation happens once per connection, never on a hot
    /// path, so the indirect call costs nothing that matters.
    pub fn allocate(&mut self, occupied: &dyn Fn(u16) -> bool) -> Option<u16> {
        let mut start = self.last.wrapping_add(1);
        if start == 0 {
            start = 1;
        }
        let mut id = start;
        let mut wrapped = false;
        loop {
            if !occupied(id) {
                self.last = id;
                return Some(id);
            }
            id = id.wrapping_add(1);
            if id == 0 {
                if wrapped {
                    return None;
                }
                id = 1;
                wrapped = true;
            }
            if wrapped && id == start {
                return None;
            }
        }
    }

    /// The last id handed out (0 before the first). Exposed for the live layer
    /// to log or inspect; not needed to drive allocation.
    pub fn last(&self) -> u16 {
        self.last
    }
}
