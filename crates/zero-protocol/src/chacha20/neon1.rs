//! Single-block NEON ChaCha20, 20 rounds unrolled.
//!
//! Four registers hold the state in row order -- w0..3 constants, w4..7 and
//! w8..11 key, w12 counter, w13..15 nonce -- and `vextq_u32` rotates the rows
//! between the column and diagonal rounds so one lane-wise quarter round covers
//! all four. The XOR is fused into the vector domain: no keystream buffer, and
//! unaligned 16-byte accesses so in-place works.
//!
//! The rounds and the rotations are spelled out as macros rather than helper
//! functions. `#[inline(always)]` cannot be combined with `#[target_feature]`,
//! and a helper that is only `#[inline]` gets outlined at the `opt-level = "s"`
//! this crate ships with -- and a single block has no instruction-level
//! parallelism to hide that behind. A macro expands where it is written, so
//! there is nothing for the inliner to get wrong.
#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::*;

/// Byte indices that rotate every 32-bit lane left by 8 inside `vqtbl1q_u8`.
///
/// A function-local `const` array would have its address taken, and the store to
/// `out` in the block epilogue is then something LLVM must assume may alias it,
/// so the mask would be reloaded after every block. It is loaded once in
/// `stream_xor` and carried through the rounds as a value instead.
const ROT8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

/// One lane-wise quarter round. Lane i is whichever of the four quarter rounds
/// the current frame has lined up; both frames of a double round use the same
/// eight operations, so this is also where the row layout pays off -- four
/// scalar quarter rounds for the price of one vector one.
///
/// The rotations are inline rather than helper calls: see the file header. rotl16
/// is one `rev32`, rotl8 is one `tbl`, and rotl12 and rotl7 are the two shifts
/// and an `orr` that a 32-bit rotate by a non-half amount costs on this ISA.
macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {{
        $a = vaddq_u32($a, $b);
        $d = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(veorq_u32($d, $a))));
        $c = vaddq_u32($c, $d);
        let t = veorq_u32($b, $c);
        $b = vorrq_u32(vshlq_n_u32(t, 12), vshrq_n_u32(t, 20));
        $a = vaddq_u32($a, $b);
        $d = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(veorq_u32($d, $a)), $m));
        $c = vaddq_u32($c, $d);
        let t = veorq_u32($b, $c);
        $b = vorrq_u32(vshlq_n_u32(t, 7), vshrq_n_u32(t, 25));
    }};
}

/// One double round: the column round, a row rotation that lines the four
/// diagonals up, the diagonal round, and the row rotation back for the next
/// column round. `vextq_u32` with the same register twice is a lane rotation,
/// one instruction.
macro_rules! dbl {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = vextq_u32($x1, $x1, 1);
        $x2 = vextq_u32($x2, $x2, 2);
        $x3 = vextq_u32($x3, $x3, 3);
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = vextq_u32($x1, $x1, 3);
        $x2 = vextq_u32($x2, $x2, 2);
        $x3 = vextq_u32($x3, $x3, 1);
    }};
}

/// The 20 rounds, as ten textual double rounds. Nothing in this path loops over
/// rounds: under `opt-level = "s"` a loop here is measurably slower than the
/// crate, and the crate is the thing being beaten.
macro_rules! rounds20 {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
    }};
}

/// `inp` and `out` may alias exactly. Writes `len` bytes, 1..=len.
///
/// The round body is written out once, inside the loop, and serves whole blocks
/// and a short last block alike: `n` is how many of this block's 64 bytes are
/// wanted, and the four branches in the epilogue are the only difference. A
/// separate tail path would be a second copy of the same 400 instructions for a
/// case that is one comparison wide.
#[target_feature(enable = "neon")]
pub(super) unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let mut st = super::initial_state(key32, nonce12, start as u32);
    let c0 = vld1q_u32(st.as_ptr());
    let k0 = vld1q_u32(st.as_ptr().add(4));
    let k1 = vld1q_u32(st.as_ptr().add(8));
    let m = vld1q_u8(ROT8.as_ptr());
    let mut off = 0usize;
    while off < len {
        let n = core::cmp::min(64, len - off);
        st[12] = (start + (off / 64) as u64) as u32;
        let o3 = vld1q_u32(st.as_ptr().add(12));

        let (mut x0, mut x1, mut x2, mut x3) = (c0, k0, k1, o3);
        rounds20!(x0, x1, x2, x3, m);
        let f0 = vaddq_u32(x0, c0);
        let f1 = vaddq_u32(x1, k0);
        let f2 = vaddq_u32(x2, k1);
        let f3 = vaddq_u32(x3, o3);

        if n >= 16 {
            vst1q_u8(
                out.add(off),
                veorq_u8(vld1q_u8(inp.add(off)), vreinterpretq_u8_u32(f0)),
            );
        }
        if n >= 32 {
            vst1q_u8(
                out.add(off + 16),
                veorq_u8(vld1q_u8(inp.add(off + 16)), vreinterpretq_u8_u32(f1)),
            );
        }
        if n >= 48 {
            vst1q_u8(
                out.add(off + 32),
                veorq_u8(vld1q_u8(inp.add(off + 32)), vreinterpretq_u8_u32(f2)),
            );
        }
        if n >= 64 {
            vst1q_u8(
                out.add(off + 48),
                veorq_u8(vld1q_u8(inp.add(off + 48)), vreinterpretq_u8_u32(f3)),
            );
        }
        // Fewer than 16 bytes left after the last whole 16-byte chunk: spill one
        // chunk of keystream and finish scalar. At most 15 iterations, and only
        // ever on the last block of a message.
        let full = n & !15;
        if full < n {
            let mut ks = [0u8; 16];
            vst1q_u8(
                ks.as_mut_ptr(),
                vreinterpretq_u8_u32(match full {
                    0 => f0,
                    16 => f1,
                    32 => f2,
                    _ => f3,
                }),
            );
            let mut i = full;
            while i < n {
                *out.add(off + i) = *inp.add(off + i) ^ ks[i & 15];
                i += 1;
            }
        }
        off += n;
    }
}
