//! Two-block NEON ChaCha20: 128 bytes per pass, two states in flight, so the
//! 65-192 byte band has instruction-level parallelism without the four-block
//! core's register pressure.
#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn rotl16(v: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
}
#[target_feature(enable = "neon")]
unsafe fn rotl8(v: uint32x4_t) -> uint32x4_t {
    let mask = [3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), vld1q_u8(mask.as_ptr())))
}
#[target_feature(enable = "neon")]
unsafe fn rotl12(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20))
}
#[target_feature(enable = "neon")]
unsafe fn rotl7(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25))
}

/// words 13..15: the nonce half, built once per call.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn nonce_half(nonce12: &[u8; 12]) -> uint32x4_t {
    let n0 = u32::from_le_bytes([nonce12[0], nonce12[1], nonce12[2], nonce12[3]]);
    let n1 = u32::from_le_bytes([nonce12[4], nonce12[5], nonce12[6], nonce12[7]]);
    let n2 = u32::from_le_bytes([nonce12[8], nonce12[9], nonce12[10], nonce12[11]]);
    let mut v = vdupq_n_u32(0);
    v = vsetq_lane_u32(n2, v, 3);
    v = vsetq_lane_u32(n1, v, 2);
    v = vsetq_lane_u32(n0, v, 1);
    v
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn tail(base: uint32x4_t, ctr: u32) -> uint32x4_t {
    vsetq_lane_u32(ctr, base, 0)
}

/// 20 rounds over 2 states at once, feed-forward included.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn rounds_two(o: [uint32x4_t; 8]) -> [uint32x4_t; 8] {
    let [a0, a1, a2, a3, b0, b1, b2, b3] = o;
    let (mut x0, mut x1, mut x2, mut x3) = (a0, a1, a2, a3);
    let (mut y0, mut y1, mut y2, mut y3) = (b0, b1, b2, b3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    [
        vaddq_u32(x0, a0),
        vaddq_u32(x1, a1),
        vaddq_u32(x2, a2),
        vaddq_u32(x3, a3),
        vaddq_u32(y0, b0),
        vaddq_u32(y1, b1),
        vaddq_u32(y2, b2),
        vaddq_u32(y3, b3),
    ]
}

/// One 128-byte group: 2 whole blocks. `bytes` is 1..=128; the ladder only ever
/// passes a short `bytes` for the last group of a message, and the branches
/// below are perfectly predicted in every other case.
#[target_feature(enable = "neon")]
pub(super) unsafe fn xor_group(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    bytes: usize,
) {
    let cs = vld1q_u32(super::CONSTS.as_ptr());
    let base = nonce_half(nonce12);
    // The two halves of the key are loaded as two vectors. `add` runs before
    // the cast, so it counts bytes: `add(4)` would read key bytes 4..20 and use
    // words 1..4 twice while never touching words 5..8. Sixteen bytes, not four.
    let k0 = vld1q_u32(key32.as_ptr() as *const u32);
    let k1 = vld1q_u32(key32.as_ptr().add(16) as *const u32);
    let mut st = [cs; 8];
    let mut b = 0;
    while b < 2 {
        let o = b * 4;
        st[o + 1] = k0;
        st[o + 2] = k1;
        st[o + 3] = tail(base, (start + b as u64) as u32);
        b += 1;
    }
    let f = rounds_two(st);
    let mut i = 0;
    while i < 8 {
        let d = i * 16;
        if d >= bytes {
            break;
        }
        if d + 16 <= bytes {
            vst1q_u8(
                out.add(d),
                veorq_u8(vld1q_u8(inp.add(d)), vreinterpretq_u8_u32(f[i])),
            );
        } else {
            // 1..=15 bytes left in this group: spill the chunk and finish
            // scalar, so nothing outside `bytes` is ever read or written.
            let n = bytes - d;
            let mut ks = [0u8; 16];
            vst1q_u8(ks.as_mut_ptr(), vreinterpretq_u8_u32(f[i]));
            let mut j = 0;
            while j < n {
                *out.add(d + j) = *inp.add(d + j) ^ ks[j];
                j += 1;
            }
        }
        i += 1;
    }
}
