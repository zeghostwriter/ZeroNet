package com.zeronet.mobile.service

import com.zeronet.mobile.model.EvasionLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LadderTest {
    @Test fun aNetworkWithNoHistoryWalksDownFromTheTop() {
        assertEquals(listOf(0, 1, 3, 4), Ladder.order(null, hasWarp = false))
        // With an account, WARP (inside WARP) goes first and the rest back it up.
        assertEquals(listOf(2, 0, 1, 3, 4), Ladder.order(null, hasWarp = true))
    }

    @Test fun theRungThatWorkedBeforeIsTriedRightAfterTheQuickFirstOne() {
        assertEquals(listOf(0, 3, 1, 4), Ladder.order(Ladder.DISGUISE, hasWarp = false))
        assertEquals(listOf(2, 0, 4, 1, 3), Ladder.order(Ladder.OPEN, hasWarp = true))
        // Remembering a rung that already leads changes nothing.
        assertEquals(listOf(2, 0, 1, 3, 4), Ladder.order(Ladder.KNOWN, hasWarp = true))
        assertEquals(listOf(2, 0, 1, 3, 4), Ladder.order(Ladder.WARP, hasWarp = true))
    }

    @Test fun aRememberedWarpRungIsDroppedWhenTheAccountIsGone() {
        assertEquals(listOf(0, 1, 3, 4), Ladder.order(Ladder.WARP, hasWarp = false))
    }

    @Test fun everyRungIsTriedOnceAndWarpLeadsWhenThereIsAnAccount() {
        for (remembered in listOf(null, 0, 1, 2, 3, 4, 9, -1)) {
            for (warp in listOf(false, true)) {
                val order = Ladder.order(remembered, warp)
                assertEquals(order.toSet().size, order.size)
                assertEquals(if (warp) Ladder.WARP else Ladder.KNOWN, order.first())
                assertTrue(order.containsAll(Ladder.rungs.indices.filter { warp || it != Ladder.WARP }))
            }
        }
    }

    @Test fun eachRungWidensWhatTheLastOneDid() {
        val r = Ladder.rungs
        assertTrue(r[Ladder.KNOWN].known && !r[Ladder.SEARCH].known)
        assertNull(r[Ladder.SEARCH].evasion)
        assertEquals(EvasionLevel.Strong, r[Ladder.DISGUISE].evasion)
        assertTrue(r[Ladder.DISGUISE].fronts > r[Ladder.SEARCH].fronts)
        assertTrue(!r[Ladder.DISGUISE].relaxed && r[Ladder.OPEN].relaxed && r[Ladder.OPEN].allowQuic)
        assertTrue(r[Ladder.WARP].warp)
    }

    @Test fun rungsAreFoundByTheirNames() {
        assertEquals(Ladder.OPEN, Ladder.indexOf("open"))
        assertNull(Ladder.indexOf("nope"))
        assertNull(Ladder.indexOf(null))
        assertEquals(Ladder.rungs.size, Ladder.rungs.map { it.id }.toSet().size)
    }
}
