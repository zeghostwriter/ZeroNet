package com.zeronet.mobile.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mirrors the Rust reference tests in `zeronet-tui/src/adaptive_speed.rs`. */
class AdaptiveFloorTest {
    private val mb = 1_000_000L

    @Test
    fun `no floor until two configs are known`() {
        val f = AdaptiveFloor()
        assertEquals(0L, f.effectiveFloorBps())
        f.record(5 * mb)
        assertNull("one config is not a comparison", f.baseline())
        assertEquals(0L, f.effectiveFloorBps())
        assertFalse(f.tooSlow(1))
    }

    @Test
    fun `a config far below recent fast ones is too slow`() {
        val f = AdaptiveFloor()
        f.record(5 * mb)
        f.record(6 * mb)
        assertEquals(5_500_000L * 2 / 5, f.effectiveFloorBps())
        assertTrue(f.tooSlow(500_000))
        assertFalse(f.tooSlow(4 * mb))
    }

    @Test
    fun `a uniformly slow network does not thrash`() {
        val f = AdaptiveFloor()
        f.record(30_000)
        f.record(28_000)
        assertFalse(f.tooSlow(27_000))
        assertTrue(f.tooSlow(3_000))
    }

    @Test
    fun `a baseline below the minimum switches the floor off`() {
        val f = AdaptiveFloor()
        f.record(1_000)
        f.record(2_000)
        assertNull(f.baseline())
        assertEquals(0L, f.effectiveFloorBps())
    }

    @Test
    fun `the baseline follows the last few configs`() {
        val f = AdaptiveFloor()
        repeat(5) { f.record(10 * mb) }
        assertEquals(10 * mb, f.baseline())
        repeat(5) { f.record(mb) }
        assertEquals("old fast readings age out", mb, f.baseline())
    }

    @Test
    fun `one fast reading alone does not condemn a config`() {
        val f = AdaptiveFloor()
        f.record(10 * mb)
        f.record(20_000)
        assertFalse(f.tooSlow(mb))
    }
}

class SustainedDownloadTest {
    @Test
    fun `light browsing is not a measurement`() {
        // A few bursts in 20 s: page loads, not a transfer that fills the pipe.
        val window = List(20) { if (it % 5 == 0) 300_000L else 0L }
        org.junit.Assert.assertNull(sustainedDownload(window))
    }

    @Test
    fun `a bulk transfer measures its median speed`() {
        val window = List(20) { if (it < 15) 2_000_000L + it else 0L }
        org.junit.Assert.assertEquals(2_000_007L, sustainedDownload(window))
    }

    @Test
    fun `clearing forgets the last network's baseline`() {
        val f = AdaptiveFloor()
        f.record(5_000_000)
        f.record(6_000_000)
        assertTrue(f.tooSlow(100_000))
        f.clear()
        assertEquals(0L, f.effectiveFloorBps())
        assertFalse(f.tooSlow(100_000))
    }
}
