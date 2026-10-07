//! ChaCha20 keystream (RFC 8439 IETF variant).
//!
//! The keystream generator the `chacha20` crate exposes is the only part of
//! `ChaCha20Poly1305` that leaves anything on the table, and it leaves a lot:
//! that crate fills its keystream buffer a whole four-block refill at a time on
//! every backend it ships, and on aarch64 it only reaches NEON behind a cfg
//! ZeroNet does not set. A VPN that pushes 1400-byte records through it pays
//! that on every packet.
//!
//! This module computes exactly the blocks asked for. [`xor_keystream`] takes a
//! buffer and a block counter and does nothing else, so the only way to use it
//! wrong is to ask for a counter range that wraps.
//!
//! Design constraints, in order:
//!
//!   * The round body is written out, not looped. ZeroNet builds at
//!     `opt-level = "s"`, where LLVM does not unroll and does not inline
//!     `#[target_feature]` helpers on request -- a rolled round loop there is
//!     slower than the code it replaces.
//!   * Nothing is ever computed and thrown away. The ladder below is 8, 4, 2, 1
//!     blocks, and a rung is only taken when the blocks still to produce are at
//!     least that many.
//!   * The one-block rung is chosen by measurement, once, because which core
//!     wins a single block is a property of the microarchitecture and not of the
//!     ISA. See [`simd_one_block`].
//!
//! Every core here is byte-identical to `chacha20` 0.9. The `tests` module
//! below asserts that against the crate, over lengths that straddle every
//! boundary in the ladder, at several block offsets, in place and
//! buffer-to-buffer.

mod avx2;
mod neon1;
mod neon2;
mod neon4;
mod neon8;
mod portable;
mod sse1;

use core::sync::atomic::{AtomicU8, Ordering};

/// `"expand 32-byte k"`.
const CONSTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// XOR `buf` with the ChaCha20 keystream for `key` and `nonce`, starting at
/// block `start_block`. In place; `buf` may be empty.
///
/// The counter is 32 bits, as IETF ChaCha20 defines it, so the caller must not
/// ask for a range that wraps: `start_block + buf.len().div_ceil(64)` must be at
/// most `2^32`. The AEAD in [`crate::chacha20poly1305`] starts at 0 or 1 and
/// cannot come close; a caller that can is a caller that wants the IETF
/// construction's undefined behaviour and gets a panic instead of quiet
/// nonsense.
///
/// # Panics
///
/// If the block range would wrap the 32-bit counter.
#[inline]
pub fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], start_block: u32, buf: &mut [u8]) {
    let blocks = buf.len().div_ceil(64) as u64;
    assert!(
        u64::from(start_block) + blocks <= u64::from(u32::MAX),
        "ChaCha20 block counter would wrap"
    );
    if buf.is_empty() {
        return;
    }
    let ptr = buf.as_mut_ptr();
    unsafe { stream_xor(key, nonce, u64::from(start_block), ptr, ptr, buf.len()) }
}

/// The 16-word IETF state. Built once per call by every core; only word 12 moves
/// as the block counter advances, so the constants and the key stay in
/// registers.
#[inline(always)]
pub(crate) fn initial_state(key32: &[u8; 32], nonce12: &[u8; 12], ctr: u32) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = CONSTS[0];
    s[1] = CONSTS[1];
    s[2] = CONSTS[2];
    s[3] = CONSTS[3];
    s[4] = u32::from_le_bytes([key32[0], key32[1], key32[2], key32[3]]);
    s[5] = u32::from_le_bytes([key32[4], key32[5], key32[6], key32[7]]);
    s[6] = u32::from_le_bytes([key32[8], key32[9], key32[10], key32[11]]);
    s[7] = u32::from_le_bytes([key32[12], key32[13], key32[14], key32[15]]);
    s[8] = u32::from_le_bytes([key32[16], key32[17], key32[18], key32[19]]);
    s[9] = u32::from_le_bytes([key32[20], key32[21], key32[22], key32[23]]);
    s[10] = u32::from_le_bytes([key32[24], key32[25], key32[26], key32[27]]);
    s[11] = u32::from_le_bytes([key32[28], key32[29], key32[30], key32[31]]);
    s[12] = ctr;
    s[13] = u32::from_le_bytes([nonce12[0], nonce12[1], nonce12[2], nonce12[3]]);
    s[14] = u32::from_le_bytes([nonce12[4], nonce12[5], nonce12[6], nonce12[7]]);
    s[15] = u32::from_le_bytes([nonce12[8], nonce12[9], nonce12[10], nonce12[11]]);
    s
}

/// The first block index for the group that starts at byte `done`.
#[inline(always)]
fn blk(start_block: u64, done: usize) -> u64 {
    start_block + (done as u64) / 64
}

// ------------------------------------------------------------------ aarch64

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if len <= 64 {
        unsafe { one_block(key32, nonce12, start_block, inp, out, len) };
        return;
    }
    // Whole groups go to the eight-block core, then the remainder is filled by
    // the widest core that still has enough blocks to run. Nothing is computed
    // and discarded: a rung is only taken when the blocks left to produce meet
    // its width, so each block is generated exactly once.
    let groups = len / 512;
    let mut done = groups * 512;
    if groups > 0 {
        unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) };
    }
    loop {
        let rem = len - done;
        if rem == 0 {
            return;
        }
        let blocks = rem.div_ceil(64);
        if blocks >= 4 {
            let n = rem.min(256);
            unsafe {
                neon4::xor_group(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    n,
                )
            };
            done += n;
        } else if blocks >= 2 {
            let n = rem.min(128);
            unsafe {
                neon2::xor_group(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    n,
                )
            };
            done += n;
        } else {
            unsafe {
                one_block(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    rem,
                )
            };
            return;
        }
    }
}

// ------------------------------------------------------------------- x86_64

#[cfg(target_arch = "x86_64")]
unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if len <= 64 {
        unsafe { one_block(key32, nonce12, start_block, inp, out, len) };
        return;
    }
    if std::arch::is_x86_feature_detected!("avx2") {
        unsafe { stream_xor_avx2(key32, nonce12, start_block, inp, out, len) }
    } else {
        unsafe { sse1::stream_xor(key32, nonce12, start_block, inp, out, len) }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn stream_xor_avx2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let groups = len / 512;
    let mut done = groups * 512;
    for g in 0..groups {
        unsafe {
            avx2::xor8(
                key32,
                nonce12,
                blk(start_block, g * 512),
                inp.add(g * 512),
                out.add(g * 512),
            )
        };
    }
    loop {
        let rem = len - done;
        if rem == 0 {
            return;
        }
        let blocks = rem.div_ceil(64);
        if blocks >= 4 {
            let n = rem.min(256);
            unsafe {
                avx2::xor4(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    n,
                )
            };
            done += n;
        } else if blocks >= 2 {
            let n = rem.min(128);
            unsafe {
                avx2::xor2(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    n,
                )
            };
            done += n;
        } else {
            unsafe {
                one_block(
                    key32,
                    nonce12,
                    blk(start_block, done),
                    inp.add(done),
                    out.add(done),
                    rem,
                )
            };
            return;
        }
    }
}

// ----------------------------------------------------------- other targets

/// A target with no hand core: the scalar one is the whole implementation. It is
/// fully unrolled rather than textbook, because it is also the one-block rung
/// everywhere else and the one-block rung is latency-bound.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { portable::stream_xor_raw(key32, nonce12, start_block, inp, out, len) }
}

// ------------------------------------------------- which one-block core wins

/// 0 = not measured yet, 1 = SIMD, 2 = scalar.
static ONE_BLOCK: AtomicU8 = AtomicU8::new(0);

/// Which one-block core this CPU prefers, measured once and then remembered.
///
/// One ChaCha block is twenty rounds of quarter round and every round depends on
/// the one before it, so a single block has no instruction-level parallelism to
/// exploit. The only question is which instruction set reaches the end of that
/// dependency chain first, and that is a property of the microarchitecture, not
/// of the ISA. Measured on this code:
///
///   * Apple silicon: the SIMD core wins, ~1.11x over the scalar one.
///     Firestorm has the issue slots to run the row rotations without costing the
///     chain anything, so four lanes cost the same latency as one.
///   * Neoverse N1: the scalar core wins, ~1.6x. `vextq_u32` and `vqtbl1q_u8` sit
///     between every pair of rounds, on the critical path, and N1 has no second
///     vector pipe to overlap them with.
///
/// Nothing in CPUID distinguishes those, and aarch64 servers, aarch64 phones and
/// x86_64 desktops are all targets, so the choice is measured. A tie within 5%
/// goes to the scalar core: it is the architecture-neutral one. Being wrong is a
/// performance bug and never a correctness one, since both cores are
/// byte-identical -- `tests` below holds that to the same standard the whole
/// module is held to.
#[inline]
fn simd_one_block() -> bool {
    match ONE_BLOCK.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let v = if calibrate_simd() { 1 } else { 2 };
    ONE_BLOCK.store(v, Ordering::Relaxed);
    v == 1
}

fn calibrate_simd() -> bool {
    use std::time::Instant;
    const REPS: usize = 3;
    const N: usize = 128;
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let src = [7u8; 64];
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let (mut ts, mut tp) = (f64::MAX, f64::MAX);
    for _ in 0..REPS {
        let t = Instant::now();
        for _ in 0..N {
            unsafe { simd_block(&key, &nonce, 0, src.as_ptr(), a.as_mut_ptr(), 64) };
        }
        ts = ts.min(t.elapsed().as_secs_f64());
        let t = Instant::now();
        for _ in 0..N {
            unsafe { portable::stream_xor_raw(&key, &nonce, 0, src.as_ptr(), b.as_mut_ptr(), 64) };
        }
        tp = tp.min(t.elapsed().as_secs_f64());
    }
    ts * 1.05 < tp
}

/// The SIMD one-block core, whatever this target calls that.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn simd_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { neon1::stream_xor(key32, nonce12, start_block, inp, out, len) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn simd_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { sse1::stream_xor(key32, nonce12, start_block, inp, out, len) }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn simd_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { portable::stream_xor_raw(key32, nonce12, start_block, inp, out, len) }
}

/// The narrowest rung, through whichever core this CPU measured as faster.
unsafe fn one_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if simd_one_block() {
        unsafe { simd_block(key32, nonce12, start_block, inp, out, len) }
    } else {
        unsafe { portable::stream_xor_raw(key32, nonce12, start_block, inp, out, len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::{ChaCha20, Key as RefKey, Nonce as RefNonce};

    fn reference(key: &[u8; 32], nonce: &[u8; 12], start_block: u64, buf: &mut [u8]) {
        let mut c = ChaCha20::new(RefKey::from_slice(key), RefNonce::from_slice(nonce));
        c.seek(start_block * 64);
        c.apply_keystream(buf);
    }

    /// Every length that takes a different branch in the ladder, plus the
    /// boundaries either side of each rung, plus a few whole-buffer sizes.
    fn lengths() -> Vec<usize> {
        let mut v: Vec<usize> = (0..=600).collect();
        v.extend([
            700, 767, 768, 769, 1000, 1023, 1024, 1025, 1536, 2048, 4096, 8192, 16384,
        ]);
        v
    }

    /// The portable backend, against the reference, across every length the
    /// sweep covers.
    ///
    /// It is the fallback for any target without a vector core, so it is the one
    /// path that has to be right on a device this test never runs on. Driving it
    /// directly means a mistake in it is caught on whatever machine is doing the
    /// testing, rather than only on the hardware that selects it.
    #[test]
    fn the_portable_backend_matches_the_reference() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
        for len in lengths() {
            // Zero plaintext makes the output the keystream itself, so it can
            // be compared with the reference directly. `stream_xor_raw` always
            // reads its input, so that buffer is a real one rather than a
            // dangling pointer.
            let plaintext = vec![0u8; len];
            let mut want = vec![0u8; len];
            let mut got = vec![0u8; len];
            reference(&key, &nonce, 0, &mut want);
            unsafe {
                portable::stream_xor_raw(
                    &key,
                    &nonce,
                    0,
                    plaintext.as_ptr(),
                    got.as_mut_ptr(),
                    len,
                );
            }
            assert_eq!(got, want, "portable backend disagrees at {len} bytes");
        }
    }

    /// Each wider rung is exercised at the first length it is responsible for,
    /// so a defect in one of them names that rung instead of surfacing as an
    /// arbitrary offset into a length sweep.
    ///
    /// `neon2` starts at 65 bytes and `neon4` at 129. Both read the second half
    /// of the key through `key32.as_ptr().add(4)`, which advances a `*const u8`
    /// by four bytes and only then casts, so it loaded key bytes 4..20 where
    /// 16..32 belong: words 1..4 were used twice and words 5..8 not at all. An
    /// all-equal key hid it, because with every word equal the overlap looks
    /// exactly like the correct load.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_first_length_of_each_wider_rung() {
        for len in [65usize, 129, 200, 256, 300, 511] {
            let key: [u8; 32] =
                core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
            let nonce: [u8; 12] =
                core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
            let mut want = vec![0u8; len];
            let mut got = vec![0u8; len];
            reference(&key, &nonce, 0, &mut want);
            xor_keystream(&key, &nonce, 0, &mut got);
            assert_eq!(
                got, want,
                "{len} bytes: the wider rung disagrees with the reference"
            );
        }
    }

    /// An all-equal key cannot tell a correct word order from an incorrect
    /// one: every lane holds the same value, so a permuted, duplicated or
    /// truncated key yields the same state and the comparison passes anyway.
    /// That is how a two-block core that read the key wrong survived a test
    /// suite that claimed to cover it. The key's halves have to differ.
    #[test]
    fn matches_the_crate() {
        let key = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let nonce = core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
        let key2 = core::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29));
        let nonce2 = core::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61));
        for (k, n) in [(&key, &nonce), (&key2, &nonce2)] {
            for start_block in [0u32, 1, 2, 7, 64, 65_535] {
                for len in lengths() {
                    let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                    let mut want = input.clone();
                    reference(k, n, u64::from(start_block), &mut want);

                    let mut got = input.clone();
                    xor_keystream(k, n, start_block, &mut got);
                    assert_eq!(want, got, "start {start_block} len {len}");
                }
            }
        }
    }

    /// The cores advance by block counts, so a length that does not fill its last
    /// group is where a write past the end would land. Every rung boundary, with
    /// a sentinel behind the buffer that has to come back untouched.
    #[test]
    fn writes_nothing_past_the_end() {
        let key = [0x3cu8; 32];
        let nonce = [0xc3u8; 12];
        for len in [
            0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257, 383,
            384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 1023, 1024, 1025, 2049,
        ] {
            let mut buf = vec![0xa5u8; len + 128];
            xor_keystream(&key, &nonce, 0, &mut buf[..len]);
            assert!(
                buf[len..].iter().all(|b| *b == 0xa5),
                "wrote past the end of a {len}-byte buffer"
            );
        }
    }

    #[test]
    #[should_panic(expected = "would wrap")]
    fn refuses_a_wrapping_counter() {
        let mut buf = [0u8; 64];
        xor_keystream(&[0u8; 32], &[0u8; 12], u32::MAX, &mut buf);
    }
}
