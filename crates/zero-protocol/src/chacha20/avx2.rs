//! Multi-block ChaCha20 on AVX2: 2, 4 and 8 blocks per pass.
//!
//! The row layout is *cheaper* here than on aarch64, which is why this uses it
//! rather than a transposed one. Each 128-bit lane of a YMM register is one
//! block's row and `_mm256_shuffle_epi32` rotates the two halves independently
//! in a single instruction, so a double round's six row rotations cost six
//! instructions per *pair* of blocks rather than six per block. rotl8 is one
//! `vpshufb`; rotl16 needs 16-bit granularity (`pshuflw` then `pshufhw`),
//! because `vpshufd` moves whole 32-bit lanes and cannot swap the halves inside
//! one.
//!
//! Every pair needs its own four rows. Sharing the constant and key rows across
//! pairs looks free and is not: the quarter round updates all four rows it is
//! given, so a shared row would advance once per pair instead of once per round
//! and the later counter rows would finish with fewer rounds than the earlier
//! ones.
#![cfg(target_arch = "x86_64")]

use core::arch::x86_64::*;

use super::CONSTS;

/// Byte indices that rotate every 32-bit lane left by 8, duplicated into both
/// 128-bit halves because `vpshufb` selects per lane.
const ROT8: [i8; 32] = [
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, //
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
];

/// Row rotations by 1, 2 and 3 lanes, at 32-bit granularity. rotl16 is not in
/// this family: `_mm256_shuffle_epi32` moves whole 32-bit lanes and so cannot
/// swap the halves *inside* one, which is exactly what rotl16 is. That needs the
/// 16-bit granularity pair, and both of those also work per 128-bit lane, which
/// is what makes them right here -- each lane is an independent block.
const ROT1: i32 = 0x39;
const ROT2: i32 = 0x4E;
const ROT3: i32 = 0x93;

macro_rules! rotl16 {
    ($v:expr) => {
        _mm256_shufflehi_epi16::<0xB1>(_mm256_shufflelo_epi16::<0xB1>($v))
    };
}

macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {{
        $a = _mm256_add_epi32($a, $b);
        $d = rotl16!(_mm256_xor_si256($d, $a));
        $c = _mm256_add_epi32($c, $d);
        let t = _mm256_xor_si256($b, $c);
        $b = _mm256_or_si256(_mm256_slli_epi32::<12>(t), _mm256_srli_epi32::<20>(t));
        $a = _mm256_add_epi32($a, $b);
        let t = _mm256_xor_si256($d, $a);
        $d = _mm256_shuffle_epi8(t, $m);
        $c = _mm256_add_epi32($c, $d);
        let t = _mm256_xor_si256($b, $c);
        $b = _mm256_or_si256(_mm256_slli_epi32::<7>(t), _mm256_srli_epi32::<25>(t));
    }};
}

macro_rules! dbl {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = _mm256_shuffle_epi32::<ROT1>($x1);
        $x2 = _mm256_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm256_shuffle_epi32::<ROT3>($x3);
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = _mm256_shuffle_epi32::<ROT3>($x1);
        $x2 = _mm256_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm256_shuffle_epi32::<ROT1>($x3);
    }};
}

/// Ten double rounds for every pair of blocks in the list. The three constant
/// and key rows are named once and listed once per pair, which is exactly why
/// widening the core costs so few registers.
macro_rules! rounds10 {
    ($m:ident; $($x0:ident $x1:ident $x2:ident $x3:ident),+ $(,)?) => {{
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
    }};
}

/// `(counter, nonce0, nonce1, nonce2)` for two consecutive blocks.
macro_rules! ctr2 {
    ($c:expr, $n0:expr, $n1:expr, $n2:expr) => {
        _mm256_setr_epi32(
            $c as i32,
            $n0,
            $n1,
            $n2,
            $c.wrapping_add(1) as i32,
            $n0,
            $n1,
            $n2,
        )
    };
}

/// One finished 64-byte block -- four 16-byte rows -- XORed into the data at
/// `$off`, writing `$n` of those 64 bytes. `$n` is 64 for every block but the
/// last of a message, so the short path is cold and the branches predict.
macro_rules! block64 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $n:expr, $off:expr, $inp:expr, $out:expr) => {{
        if $n >= 16 {
            _mm_storeu_si128(
                $out.add($off).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128($inp.add($off).cast::<__m128i>()), $a),
            );
        }
        if $n >= 32 {
            _mm_storeu_si128(
                $out.add($off + 16).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128($inp.add($off + 16).cast::<__m128i>()), $b),
            );
        }
        if $n >= 48 {
            _mm_storeu_si128(
                $out.add($off + 32).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128($inp.add($off + 32).cast::<__m128i>()), $c),
            );
        }
        if $n >= 64 {
            _mm_storeu_si128(
                $out.add($off + 48).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128($inp.add($off + 48).cast::<__m128i>()), $d),
            );
        }
        // Fewer than 16 bytes left after the last whole 16-byte chunk.
        let full = $n & !15;
        if full < $n {
            let mut ks = [0u8; 16];
            let f = match full {
                0 => $a,
                16 => $b,
                32 => $c,
                _ => $d,
            };
            _mm_storeu_si128(ks.as_mut_ptr().cast::<__m128i>(), f);
            let mut i = full;
            while i < $n {
                *$out.add($off + i) = *$inp.add($off + i) ^ ks[i & 15];
                i += 1;
            }
        }
    }};
}

/// A 128-byte pair. Each block is one 128-bit lane of each row, so the two
/// blocks are stored separately: one 32-byte store would put the second block's
/// first row 32 bytes from the first block's instead of 64. `$want` is how many
/// of this pair's 128 bytes the caller wants, clamped here so that a wider
/// caller cannot overrun its own group.
macro_rules! emit_pair {
    ($x0:ident, $x1:ident, $x2:ident, $y3:ident, $off:expr, $want:expr, $inp:expr, $out:expr) => {{
        let n = core::cmp::min($want, 128);
        block64!(
            _mm256_castsi256_si128($x0),
            _mm256_castsi256_si128($x1),
            _mm256_castsi256_si128($x2),
            _mm256_castsi256_si128($y3),
            core::cmp::min(n, 64),
            $off,
            $inp,
            $out
        );
        if n > 64 {
            block64!(
                _mm256_extracti128_si256::<1>($x0),
                _mm256_extracti128_si256::<1>($x1),
                _mm256_extracti128_si256::<1>($x2),
                _mm256_extracti128_si256::<1>($y3),
                n - 64,
                $off + 64,
                $inp,
                $out
            );
        }
    }};
}

/// Two blocks, 128 bytes. `bytes` is 1..=128; the ladder only ever passes a
/// short `bytes` for the last group of a message.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn xor2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    bytes: usize,
) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let cst = _mm256_broadcastsi128_si256(_mm_loadu_si128(CONSTS.as_ptr().cast::<__m128i>()));
    let k0v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(4).cast::<__m128i>()));
    let k1v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(8).cast::<__m128i>()));
    let m = _mm256_loadu_si256(ROT8.as_ptr().cast::<__m256i>());
    let a3o = ctr2!(st[12], st[13] as i32, st[14] as i32, st[15] as i32);

    let (mut a0, mut a1, mut a2) = (cst, k0v, k1v);
    let mut a3 = a3o;
    rounds10!(m; a0 a1 a2 a3);

    let f0 = _mm256_add_epi32(a0, cst);
    let f1 = _mm256_add_epi32(a1, k0v);
    let f2 = _mm256_add_epi32(a2, k1v);
    let f3 = _mm256_add_epi32(a3, a3o);
    emit_pair!(f0, f1, f2, f3, 0, bytes, inp, out);
}

/// Four blocks, 256 bytes. `bytes` is 1..=256, as for `xor2`.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn xor4(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    bytes: usize,
) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let cst = _mm256_broadcastsi128_si256(_mm_loadu_si128(CONSTS.as_ptr().cast::<__m128i>()));
    let k0v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(4).cast::<__m128i>()));
    let k1v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(8).cast::<__m128i>()));
    let m = _mm256_loadu_si256(ROT8.as_ptr().cast::<__m256i>());
    let c = st[12];
    let (n0, n1, n2) = (st[13] as i32, st[14] as i32, st[15] as i32);
    let a3o = ctr2!(c, n0, n1, n2);
    let b3o = ctr2!(c.wrapping_add(2), n0, n1, n2);

    let (mut a0, mut a1, mut a2) = (cst, k0v, k1v);
    let (mut b0, mut b1, mut b2) = (cst, k0v, k1v);
    let (mut a3, mut b3) = (a3o, b3o);
    rounds10!(m; a0 a1 a2 a3, b0 b1 b2 b3);

    let f0 = _mm256_add_epi32(a0, cst);
    let f1 = _mm256_add_epi32(a1, k0v);
    let f2 = _mm256_add_epi32(a2, k1v);
    let f3 = _mm256_add_epi32(a3, a3o);
    let g0 = _mm256_add_epi32(b0, cst);
    let g1 = _mm256_add_epi32(b1, k0v);
    let g2 = _mm256_add_epi32(b2, k1v);
    let g3 = _mm256_add_epi32(b3, b3o);
    emit_pair!(f0, f1, f2, f3, 0, bytes, inp, out);
    emit_pair!(g0, g1, g2, g3, 128, bytes.saturating_sub(128), inp, out);
}

/// Eight blocks, 512 bytes. Always whole: the ladder sizes this rung in bytes
/// precisely so that a short message never lands here.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn xor8(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let cst = _mm256_broadcastsi128_si256(_mm_loadu_si128(CONSTS.as_ptr().cast::<__m128i>()));
    let k0v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(4).cast::<__m128i>()));
    let k1v = _mm256_broadcastsi128_si256(_mm_loadu_si128(st.as_ptr().add(8).cast::<__m128i>()));
    let m = _mm256_loadu_si256(ROT8.as_ptr().cast::<__m256i>());
    let c = st[12];
    let (n0, n1, n2) = (st[13] as i32, st[14] as i32, st[15] as i32);
    let a3o = ctr2!(c, n0, n1, n2);
    let b3o = ctr2!(c.wrapping_add(2), n0, n1, n2);
    let c3o = ctr2!(c.wrapping_add(4), n0, n1, n2);
    let d3o = ctr2!(c.wrapping_add(6), n0, n1, n2);

    let (mut a0, mut a1, mut a2) = (cst, k0v, k1v);
    let (mut b0, mut b1, mut b2) = (cst, k0v, k1v);
    let (mut c0, mut c1, mut c2) = (cst, k0v, k1v);
    let (mut d0, mut d1, mut d2) = (cst, k0v, k1v);
    let (mut a3, mut b3, mut c3, mut d3) = (a3o, b3o, c3o, d3o);
    rounds10!(m; a0 a1 a2 a3, b0 b1 b2 b3, c0 c1 c2 c3, d0 d1 d2 d3);

    let f0 = _mm256_add_epi32(a0, cst);
    let f1 = _mm256_add_epi32(a1, k0v);
    let f2 = _mm256_add_epi32(a2, k1v);
    let f3 = _mm256_add_epi32(a3, a3o);
    let g0 = _mm256_add_epi32(b0, cst);
    let g1 = _mm256_add_epi32(b1, k0v);
    let g2 = _mm256_add_epi32(b2, k1v);
    let g3 = _mm256_add_epi32(b3, b3o);
    let h0 = _mm256_add_epi32(c0, cst);
    let h1 = _mm256_add_epi32(c1, k0v);
    let h2 = _mm256_add_epi32(c2, k1v);
    let h3 = _mm256_add_epi32(c3, c3o);
    let i0 = _mm256_add_epi32(d0, cst);
    let i1 = _mm256_add_epi32(d1, k0v);
    let i2 = _mm256_add_epi32(d2, k1v);
    let i3 = _mm256_add_epi32(d3, d3o);
    emit_pair!(f0, f1, f2, f3, 0, 128, inp, out);
    emit_pair!(g0, g1, g2, g3, 128, 128, inp, out);
    emit_pair!(h0, h1, h2, h3, 256, 128, inp, out);
    emit_pair!(i0, i1, i2, i3, 384, 128, inp, out);
}
