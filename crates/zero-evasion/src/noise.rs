//! UDP noise.
//!
//! Prepending decoy datagrams before the real payload breaks flow classifiers
//! that fingerprint the first packet of a UDP flow. BPB applies this to
//! Cloudflare's HTTPS ports, where QUIC is otherwise trivially recognised
//! (PLAN-02 §3.2).
//!
//! Absent from every Rust proxy core surveyed.

use std::time::Duration;

use crate::rand_between::rand_between;

/// One decoy packet specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoisePacket {
    /// Random bytes, with a length range and a value range.
    Rand {
        length_min: i64,
        length_max: i64,
        byte_min: u8,
        byte_max: u8,
    },
    /// Fixed bytes.
    Fixed(Vec<u8>),
    /// QUIC Initial-shaped bytes for a classifier knock. This is deliberately
    /// only a decoy header; it is never handed to a QUIC implementation.
    Quic { length_min: i64, length_max: i64 },
}

impl NoisePacket {
    /// Materialise one datagram.
    pub fn generate(&self) -> Vec<u8> {
        match self {
            NoisePacket::Rand {
                length_min,
                length_max,
                byte_min,
                byte_max,
            } => {
                use rand::{Rng, RngCore};
                let len = rand_between(*length_min, *length_max).max(0) as usize;
                // Same distribution as drawing `rand_between(min, max + 1)` per
                // byte (swap and span-of-one quirks included), but from one
                // RNG handle and, for the full byte range, one bulk fill.
                let (lo, hi) = {
                    let (a, b) = (*byte_min as i64, *byte_max as i64 + 1);
                    if a > b {
                        (b, a)
                    } else {
                        (a, b)
                    }
                };
                let mut rng = rand::thread_rng();
                let mut packet = vec![0u8; len];
                match hi - lo {
                    0 | 1 => packet.fill(lo as u8),
                    256 => rng.fill_bytes(&mut packet),
                    _ => {
                        let range = rand::distributions::Uniform::new(lo, hi);
                        for byte in &mut packet {
                            *byte = rng.sample(range) as u8;
                        }
                    }
                }
                packet
            }
            NoisePacket::Fixed(b) => b.clone(),
            NoisePacket::Quic {
                length_min,
                length_max,
            } => {
                use rand::RngCore;
                let length = rand_between(*length_min, *length_max).max(25) as usize;
                let mut packet = vec![0u8; length];
                rand::rngs::OsRng.fill_bytes(&mut packet);
                // QUIC long header, version 1, 8-byte destination and source
                // connection IDs, empty token, and a short length varint.
                packet[0] = 0xc0 | (packet[0] & 0x0f);
                packet[1..5].copy_from_slice(&1u32.to_be_bytes());
                packet[5] = 8;
                packet[14] = 8;
                packet[23] = 0;
                packet
            }
        }
    }
}

/// One entry in a noise plan: a packet, repeated `count` times, each followed
/// by a delay drawn from the range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseEntry {
    pub packet: NoisePacket,
    pub delay_min_ms: i64,
    pub delay_max_ms: i64,
    pub count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoisePolicy {
    pub entries: Vec<NoiseEntry>,
}

impl NoisePolicy {
    /// BPB's field-tuned default: five random 50-100 byte datagrams, 1-5 ms
    /// apart.
    pub fn bpb_default() -> Self {
        Self {
            entries: vec![NoiseEntry {
                packet: NoisePacket::Rand {
                    length_min: 50,
                    length_max: 100,
                    byte_min: 0,
                    byte_max: 255,
                },
                delay_min_ms: 1,
                delay_max_ms: 5,
                count: 5,
            }],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| e.count == 0)
    }

    /// Expand into the concrete datagrams to send, each with its trailing
    /// delay. Every call re-randomises, so two flows never emit the same
    /// decoy sequence.
    pub fn plan(&self) -> Vec<(Vec<u8>, Duration)> {
        let mut out = Vec::new();
        for entry in &self.entries {
            for _ in 0..entry.count {
                let delay = rand_between(entry.delay_min_ms, entry.delay_max_ms).max(0);
                out.push((entry.packet.generate(), Duration::from_millis(delay as u64)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpb_default_expands_to_five_packets() {
        let plan = NoisePolicy::bpb_default().plan();
        assert_eq!(plan.len(), 5);
        for (bytes, delay) in &plan {
            assert!((50..100).contains(&bytes.len()), "len {}", bytes.len());
            assert!(*delay <= Duration::from_millis(5));
        }
    }

    #[test]
    fn fixed_packets_are_verbatim() {
        let p = NoisePacket::Fixed(vec![1, 2, 3]);
        assert_eq!(p.generate(), vec![1, 2, 3]);
    }

    #[test]
    fn byte_range_is_respected() {
        let p = NoisePacket::Rand {
            length_min: 64,
            length_max: 65,
            byte_min: 10,
            byte_max: 20,
        };
        let b = p.generate();
        assert_eq!(b.len(), 64);
        assert!(b.iter().all(|x| (10..=20).contains(x)), "out of range");
    }

    #[test]
    fn single_value_and_full_byte_ranges() {
        let constant = NoisePacket::Rand {
            length_min: 32,
            length_max: 32,
            byte_min: 7,
            byte_max: 7,
        }
        .generate();
        assert_eq!(constant, vec![7u8; 32]);

        let full = NoisePacket::Rand {
            length_min: 4096,
            length_max: 4096,
            byte_min: 0,
            byte_max: 255,
        }
        .generate();
        assert_eq!(full.len(), 4096);
        assert!(full.iter().any(|b| *b > 200) && full.iter().any(|b| *b < 50));
    }

    #[test]
    fn empty_policy_plans_nothing() {
        assert!(NoisePolicy::default().plan().is_empty());
        assert!(NoisePolicy::default().is_empty());
    }

    #[test]
    fn successive_plans_differ() {
        let p = NoisePolicy::bpb_default();
        // With 50-100 random bytes, identical consecutive plans are
        // vanishingly unlikely; a match means the RNG is not being drawn.
        assert_ne!(p.plan(), p.plan());
    }

    #[test]
    fn quic_noise_has_a_long_header_shape() {
        let packet = NoisePacket::Quic {
            length_min: 5,
            length_max: 10,
        }
        .generate();
        assert!(packet.len() >= 25);
        assert_eq!(packet[0] & 0x80, 0x80);
        assert_eq!(&packet[1..5], &1u32.to_be_bytes());
        assert_eq!(packet[5], 8);
        assert_eq!(packet[14], 8);
        assert_eq!(packet[23], 0);
    }
}
