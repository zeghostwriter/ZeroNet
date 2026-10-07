//! The static Huffman code of RFC 7541 Appendix B, shared by HPACK and
//! QPACK (RFC 9204 §4.1.2). Only decoding is needed here: the requests the
//! MASQUE client sends are written out without Huffman coding.

use std::sync::OnceLock;

/// `(bit length, code)` for each octet value, and the end-of-string symbol
/// last. Codes are right-aligned.
const TABLE: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x7fffd8),
    (28, 0xfffffe2),
    (28, 0xfffffe3),
    (28, 0xfffffe4),
    (28, 0xfffffe5),
    (28, 0xfffffe6),
    (28, 0xfffffe7),
    (28, 0xfffffe8),
    (24, 0xffffea),
    (30, 0x3ffffffc),
    (28, 0xfffffe9),
    (28, 0xfffffea),
    (30, 0x3ffffffd),
    (28, 0xfffffeb),
    (28, 0xfffffec),
    (28, 0xfffffed),
    (28, 0xfffffee),
    (28, 0xfffffef),
    (28, 0xffffff0),
    (28, 0xffffff1),
    (28, 0xffffff2),
    (30, 0x3ffffffe),
    (28, 0xffffff3),
    (28, 0xffffff4),
    (28, 0xffffff5),
    (28, 0xffffff6),
    (28, 0xffffff7),
    (28, 0xffffff8),
    (28, 0xffffff9),
    (28, 0xffffffa),
    (28, 0xffffffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0xffffffc),
    (20, 0xfffe6),
    (22, 0x3fffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x3fffd3),
    (22, 0x3fffd4),
    (22, 0x3fffd5),
    (23, 0x7fffd9),
    (22, 0x3fffd6),
    (23, 0x7fffda),
    (23, 0x7fffdb),
    (23, 0x7fffdc),
    (23, 0x7fffdd),
    (23, 0x7fffde),
    (24, 0xffffeb),
    (23, 0x7fffdf),
    (24, 0xffffec),
    (24, 0xffffed),
    (22, 0x3fffd7),
    (23, 0x7fffe0),
    (24, 0xffffee),
    (23, 0x7fffe1),
    (23, 0x7fffe2),
    (23, 0x7fffe3),
    (23, 0x7fffe4),
    (21, 0x1fffdc),
    (22, 0x3fffd8),
    (23, 0x7fffe5),
    (22, 0x3fffd9),
    (23, 0x7fffe6),
    (23, 0x7fffe7),
    (24, 0xffffef),
    (22, 0x3fffda),
    (21, 0x1fffdd),
    (20, 0xfffe9),
    (22, 0x3fffdb),
    (22, 0x3fffdc),
    (23, 0x7fffe8),
    (23, 0x7fffe9),
    (21, 0x1fffde),
    (23, 0x7fffea),
    (22, 0x3fffdd),
    (22, 0x3fffde),
    (24, 0xfffff0),
    (21, 0x1fffdf),
    (22, 0x3fffdf),
    (23, 0x7fffeb),
    (23, 0x7fffec),
    (21, 0x1fffe0),
    (21, 0x1fffe1),
    (22, 0x3fffe0),
    (21, 0x1fffe2),
    (23, 0x7fffed),
    (22, 0x3fffe1),
    (23, 0x7fffee),
    (23, 0x7fffef),
    (20, 0xfffea),
    (22, 0x3fffe2),
    (22, 0x3fffe3),
    (22, 0x3fffe4),
    (23, 0x7ffff0),
    (22, 0x3fffe5),
    (22, 0x3fffe6),
    (23, 0x7ffff1),
    (26, 0x3ffffe0),
    (26, 0x3ffffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x3fffe7),
    (23, 0x7ffff2),
    (22, 0x3fffe8),
    (25, 0x1ffffec),
    (26, 0x3ffffe2),
    (26, 0x3ffffe3),
    (26, 0x3ffffe4),
    (27, 0x7ffffde),
    (27, 0x7ffffdf),
    (26, 0x3ffffe5),
    (24, 0xfffff1),
    (25, 0x1ffffed),
    (19, 0x7fff2),
    (21, 0x1fffe3),
    (26, 0x3ffffe6),
    (27, 0x7ffffe0),
    (27, 0x7ffffe1),
    (26, 0x3ffffe7),
    (27, 0x7ffffe2),
    (24, 0xfffff2),
    (21, 0x1fffe4),
    (21, 0x1fffe5),
    (26, 0x3ffffe8),
    (26, 0x3ffffe9),
    (28, 0xffffffd),
    (27, 0x7ffffe3),
    (27, 0x7ffffe4),
    (27, 0x7ffffe5),
    (20, 0xfffec),
    (24, 0xfffff3),
    (20, 0xfffed),
    (21, 0x1fffe6),
    (22, 0x3fffe9),
    (21, 0x1fffe7),
    (21, 0x1fffe8),
    (23, 0x7ffff3),
    (22, 0x3fffea),
    (22, 0x3fffeb),
    (25, 0x1ffffee),
    (25, 0x1ffffef),
    (24, 0xfffff4),
    (24, 0xfffff5),
    (26, 0x3ffffea),
    (23, 0x7ffff4),
    (26, 0x3ffffeb),
    (27, 0x7ffffe6),
    (26, 0x3ffffec),
    (26, 0x3ffffed),
    (27, 0x7ffffe7),
    (27, 0x7ffffe8),
    (27, 0x7ffffe9),
    (27, 0x7ffffea),
    (27, 0x7ffffeb),
    (28, 0xffffffe),
    (27, 0x7ffffec),
    (27, 0x7ffffed),
    (27, 0x7ffffee),
    (27, 0x7ffffef),
    (27, 0x7fffff0),
    (26, 0x3ffffee),
    (30, 0x3fffffff),
];

/// One node of the prefix-code trie: which child follows a `0` or `1` bit, and
/// the symbol that terminates here (if any). `NONE` child means no codeword has
/// that prefix; `NOT_LEAF` means this node is interior, not a code.
struct Node {
    child: [u32; 2],
    symbol: u16,
}

const NONE: u32 = u32::MAX;
const NOT_LEAF: u16 = u16::MAX;

/// The whole decode trie, flat in one `Vec` so a step is an indexed load. Built
/// once from `TABLE` (the RFC's own code assignment), so the walk and the
/// textbook scan can only ever agree: they read the same edges.
struct Trie {
    nodes: Vec<Node>,
}

/// Fold `TABLE` into a binary trie. Each codeword is laid down most-significant
/// bit first; a prefix code guarantees no code is a prefix of another, so a
/// codeword always ends on a fresh interior node and no terminal ever grows a
/// child.
fn build_trie() -> Trie {
    let mut nodes = vec![Node {
        child: [NONE, NONE],
        symbol: NOT_LEAF,
    }];
    for (symbol, &(len, value)) in TABLE.iter().enumerate() {
        let mut cur = 0usize;
        for k in (0..len as u32).rev() {
            let bit = ((value >> k) & 1) as usize;
            let next = nodes[cur].child[bit];
            cur = if next == NONE {
                let idx = nodes.len() as u32;
                nodes.push(Node {
                    child: [NONE, NONE],
                    symbol: NOT_LEAF,
                });
                nodes[cur].child[bit] = idx;
                idx as usize
            } else {
                next as usize
            };
        }
        debug_assert_eq!(nodes[cur].symbol, NOT_LEAF, "codeword is a prefix");
        nodes[cur].symbol = symbol as u16;
    }
    Trie { nodes }
}

static TRIE: OnceLock<Trie> = OnceLock::new();

/// Decode a Huffman-coded string. `None` for anything RFC 7541 §5.2 says is a
/// decoding error: the end-of-string symbol inside the data, or padding that
/// is longer than seven bits or is not all ones.
///
/// The code is a prefix code, so the moment the bits since the last emitted
/// symbol trace a complete codeword, that symbol is determined and no later bits
/// can change it — exactly where the textbook "scan the table for a matching
/// `(length, value)`" fires. One indexed step per bit replaces a 257-entry scan
/// per bit, for identical output.
///
/// Both error paths fold onto the walk. A bit with no child is a prefix no
/// codeword extends, which the scan would also never match; and the padding
/// check needs only the leftover bit count and whether they were all ones, since
/// a leftover segment's code is `(1 << bits) - 1` precisely then.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let trie = TRIE.get_or_init(build_trie);
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut cur = 0usize;
    let mut depth = 0u32;
    let mut all_ones = true;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as usize;
            let next = trie.nodes[cur].child[bit];
            if next == NONE {
                return None;
            }
            cur = next as usize;
            depth += 1;
            all_ones &= bit == 1;
            let symbol = trie.nodes[cur].symbol;
            if symbol != NOT_LEAF {
                if symbol == 256 {
                    return None;
                }
                out.push(symbol as u8);
                cur = 0;
                depth = 0;
                all_ones = true;
            }
        }
    }
    if depth > 7 || !all_ones {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verbatim copy of the shipped pre-trie decoder — the linear per-bit
    /// table scan. Kept only so every test can assert the trie agrees with it
    /// byte for byte, including on the inputs it rejects.
    fn decode_scan(input: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut code: u32 = 0;
        let mut bits: u8 = 0;
        for byte in input {
            for shift in (0..8).rev() {
                code = (code << 1) | u32::from((byte >> shift) & 1);
                bits += 1;
                if bits > 30 {
                    return None;
                }
                if let Some(symbol) = TABLE
                    .iter()
                    .position(|&(len, value)| len == bits && value == code)
                {
                    if symbol == 256 {
                        return None;
                    }
                    out.push(symbol as u8);
                    code = 0;
                    bits = 0;
                }
            }
        }
        if bits > 7 || code != (1u32 << bits) - 1 {
            return None;
        }
        Some(out)
    }

    /// Huffman-encode `data` with `TABLE`, padding the tail with ones to the
    /// byte boundary exactly as the RFC's end-of-string prefix allows.
    fn encode_bytes(data: &[u8]) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        for &b in data {
            let (len, code) = TABLE[b as usize];
            for k in (0..len as u32).rev() {
                bits.push(((code >> k) & 1) as u8);
            }
        }
        // Pad the tail with ones up to the next byte boundary (the RFC lets a
        // encoded string end with the all-ones end-of-string prefix).
        let pad = (8 - bits.len() % 8) % 8;
        bits.resize(bits.len() + pad, 1);
        let mut out = vec![0u8; bits.len() / 8];
        for (i, &bit) in bits.iter().enumerate() {
            out[i / 8] |= bit << (7 - (i % 8));
        }
        out
    }

    fn xorshift(mut s: u64) -> impl FnMut() -> u64 {
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        }
    }

    /// Every one- and two-byte input, 65 792 of them: the trie must match the
    /// scan on all, both in the bytes it emits and in the inputs it rejects.
    #[test]
    fn trie_matches_the_scan_on_every_short_input() {
        for a in 0u16..=255 {
            let one = [a as u8];
            assert_eq!(decode(&one), decode_scan(&one), "input {one:?}");
            for b in 0u16..=255 {
                let two = [a as u8, b as u8];
                assert_eq!(decode(&two), decode_scan(&two), "input {two:?}");
            }
        }
    }

    /// Round-trip: every single symbol decodes back to itself, and random
    /// multi-symbol payloads decode back exactly — the trie equals the scan and
    /// both equal the original bytes.
    #[test]
    fn trie_decodes_every_valid_encoding_like_the_scan() {
        for symbol in 0u16..=255 {
            let data = [symbol as u8];
            let coded = encode_bytes(&data);
            assert_eq!(decode(&coded).as_deref(), Some(&data[..]));
            assert_eq!(decode(&coded), decode_scan(&coded));
        }
        let mut rnd = xorshift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200_000 {
            let n = (rnd() % 48) as usize;
            let data: Vec<u8> = (0..n).map(|_| (rnd() % 256) as u8).collect();
            let coded = encode_bytes(&data);
            assert_eq!(decode(&coded), decode_scan(&coded));
            assert_eq!(decode(&coded).as_deref(), Some(&data[..]));
        }
    }

    /// Random arbitrary bytes are mostly invalid, which is where the two error
    /// paths (dead-end prefix vs the thirty-bit cutoff, and the padding rule)
    /// could in principle disagree. They never do.
    #[test]
    fn trie_matches_the_scan_on_random_arbitrary_bytes() {
        let mut rnd = xorshift(0x1234_5678_9abc_def0);
        for _ in 0..400_000 {
            let n = (rnd() % 40) as usize;
            let input: Vec<u8> = (0..n).map(|_| (rnd() % 256) as u8).collect();
            assert_eq!(decode(&input), decode_scan(&input), "input {input:?}");
        }
        // All-ones and near-all-ones streams stress the padding/EOS boundary.
        for len in 0..=40usize {
            let ones = vec![0xffu8; len];
            assert_eq!(decode(&ones), decode_scan(&ones), "ones len {len}");
            let mut mixed = ones.clone();
            if let Some(last) = mixed.last_mut() {
                *last = 0x7f;
            }
            assert_eq!(decode(&mixed), decode_scan(&mixed));
        }
    }

    /// RFC 7541 C.4.1: "www.example.com".
    #[test]
    fn decodes_the_rfc_examples() {
        let coded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(decode(&coded).as_deref(), Some(&b"www.example.com"[..]));
        // RFC 7541 C.6.1: "302".
        assert_eq!(decode(&[0x64, 0x02]).as_deref(), Some(&b"302"[..]));
    }

    #[test]
    fn refuses_bad_padding_and_the_end_symbol() {
        // '0' is the five-bit code 00000, followed by three padding ones.
        assert_eq!(decode(&[0x07]).as_deref(), Some(&b"0"[..]));
        // The same with the padding cleared.
        assert_eq!(decode(&[0x00]), None);
        // Eight bits of padding is a whole byte too many.
        assert_eq!(decode(&[0x07, 0xff]), None);
        // The end-of-string symbol inside the data.
        assert_eq!(decode(&[0xff, 0xff, 0xff, 0xff]), None);
    }
}
