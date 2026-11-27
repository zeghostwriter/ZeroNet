package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.home.Lod
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LodTest {
    @Test fun aPlanetThatFillsTheScreenShowsEverything() {
        val near = Lod.of(134f)
        assertEquals(1f, near.medium, 0f)
        assertEquals(1f, near.fine, 0f)
        assertEquals(1, near.coastStride)
        assertEquals(0, near.minRing)
    }

    @Test fun aDistantOneShowsOnlyTheDisc() {
        val far = Lod.of(8f)
        assertEquals(0f, far.medium, 0f)
        assertEquals(0f, far.fine, 0f)
        assertTrue(far.coastStride >= 8)
        assertTrue(far.minRing >= 12)
    }

    @Test fun detailNeverGrowsAsAPlanetShrinks() {
        var lastMedium = 1f
        var lastFine = 1f
        var lastStride = 1
        var lastRing = 0
        for (r in 140 downTo 1) {
            val d = Lod.of(r.toFloat())
            assertTrue(d.medium <= lastMedium + 1e-6f && d.fine <= lastFine + 1e-6f)
            assertTrue(d.coastStride >= lastStride && d.minRing >= lastRing)
            assertTrue(d.medium in 0f..1f && d.fine in 0f..1f)
            lastMedium = d.medium; lastFine = d.fine; lastStride = d.coastStride; lastRing = d.minRing
        }
    }

    @Test fun theFineDetailComesInAfterTheMediumAndFadesRatherThanPopping() {
        val mid = Lod.of((Lod.FINE_FROM + Lod.FINE_FULL) / 2f)
        assertTrue(mid.fine in 0.3f..0.7f)
        assertEquals(1f, mid.medium, 0f)
        var last = 0f
        for (i in 0..100) {
            val f = Lod.of(Lod.FINE_FROM + (Lod.FINE_FULL - Lod.FINE_FROM) * i / 100f).fine
            assertTrue(f - last < 0.06f)
            last = f
        }
    }
}
