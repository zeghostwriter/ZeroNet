//! The messages a reverse-proxy portal sends its bridge, Xray's `Control`.
//!
//! A portal and a bridge share one mux carrier. Besides the user sessions, the
//! portal opens a UDP session to the name `reverse` and writes a small
//! protobuf message there every few seconds:
//!
//! ```text
//! message Control { State state = 1; bytes random = 99; }   // ACTIVE = 0, DRAIN = 1
//! ```
//!
//! `state` tells the bridge whether to keep counting this carrier (`DRAIN`
//! means "open another one, this one is full"); `random` is padding of a
//! different length each time so the heartbeat has no fixed size. A message
//! that is all defaults is empty on the wire, so the bridge treats "no
//! `state` field" as `ACTIVE`.

/// The name of the control session. Both ends must use exactly this.
pub const CONTROL_HOST: &str = "reverse";

/// What the portal says about a carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    Drain,
}

fn varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// One heartbeat: `state`, plus `padding` random-looking bytes (field 99).
pub fn encode(state: State, padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(padding.len() + 6);
    if state == State::Drain {
        out.extend_from_slice(&[0x08, 0x01]);
    }
    if !padding.is_empty() {
        // Field 99, wire type 2 (length-delimited): tag 99 << 3 | 2 = 794.
        varint(99 << 3 | 2, &mut out);
        varint(padding.len(), &mut out);
        out.extend_from_slice(padding);
    }
    out
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The state a heartbeat names. Unknown fields are skipped, as protobuf
/// readers do; `None` means the bytes are not a protobuf message at all.
pub fn decode(bytes: &[u8]) -> Option<State> {
    let mut at = 0;
    let mut state = State::Active;
    while at < bytes.len() {
        let tag = read_varint(bytes, &mut at)?;
        match tag & 7 {
            0 => {
                let value = read_varint(bytes, &mut at)?;
                if tag >> 3 == 1 {
                    state = if value == 1 {
                        State::Drain
                    } else {
                        State::Active
                    };
                }
            }
            2 => {
                let len = read_varint(bytes, &mut at)?;
                at = at.checked_add(len).filter(|end| *end <= bytes.len())?;
            }
            1 => at = at.checked_add(8).filter(|end| *end <= bytes.len())?,
            5 => at = at.checked_add(4).filter(|end| *end <= bytes.len())?,
            _ => return None,
        }
    }
    Some(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heartbeat_reads_back() {
        for state in [State::Active, State::Drain] {
            for padding in [&b""[..], &[7u8; 5][..], &[1u8; 300][..]] {
                assert_eq!(decode(&encode(state, padding)), Some(state));
            }
        }
    }

    #[test]
    fn the_wire_form_is_what_xray_writes() {
        // `Control{state: DRAIN, random: "ab"}` from the protobuf definition.
        assert_eq!(
            encode(State::Drain, b"ab"),
            [0x08, 0x01, 0x9a, 0x06, 0x02, b'a', b'b']
        );
        // ACTIVE is the default, so it is not written at all.
        assert_eq!(encode(State::Active, b""), Vec::<u8>::new());
    }

    #[test]
    fn nonsense_is_not_a_heartbeat() {
        assert_eq!(decode(&[0x9a, 0x06, 0x05, 1]), None, "length past the end");
        assert_eq!(decode(&[0xff]), None, "unfinished varint");
        assert_eq!(decode(&[0x07]), None, "unknown wire type");
    }
}
