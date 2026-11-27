package com.zeronet.mobile.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GameTuneTest {
    @Test fun aSteadyServerBeatsAFasterButWanderingOne() {
        val steady = GameTune.score(listOf(90, 92, 91))
        val wandering = GameTune.score(listOf(60, 300, 65))
        assertTrue(steady < wandering)
        val picked = GameTune.pick(mapOf("steady" to listOf(90, 92, 91), "wandering" to listOf(60, 300, 65)), current = null)
        assertEquals("steady", picked)
    }

    @Test fun everyLostAttemptCostsALot() {
        assertTrue(GameTune.score(listOf(80, -1, 82)) > GameTune.score(listOf(140, 141, 139)))
        assertEquals(Double.MAX_VALUE, GameTune.score(listOf(-1, -1, -1)), 0.0)
        assertEquals(Double.MAX_VALUE, GameTune.score(emptyList()), 0.0)
    }

    @Test fun aServerIsNotSwitchedForAMarginalGain() {
        val results = mapOf("now" to listOf(100, 100, 100), "other" to listOf(92, 92, 92))
        assertEquals("now", GameTune.pick(results, current = "now"))
        val clearlyBetter = mapOf("now" to listOf(100, 100, 100), "other" to listOf(60, 60, 60))
        assertEquals("other", GameTune.pick(clearlyBetter, current = "now"))
    }

    @Test fun aDeadCurrentServerIsAlwaysLeftAndNothingWorkingGivesNothing() {
        val results = mapOf("now" to listOf(-1, -1, -1), "other" to listOf(200, 210, 190))
        assertEquals("other", GameTune.pick(results, current = "now"))
        assertNull(GameTune.pick(mapOf("a" to listOf(-1), "b" to emptyList()), current = "a"))
        assertNull(GameTune.pick(emptyMap(), current = null))
    }
}
