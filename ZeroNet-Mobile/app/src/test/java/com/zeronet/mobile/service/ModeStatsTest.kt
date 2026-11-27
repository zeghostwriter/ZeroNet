package com.zeronet.mobile.service

import com.zeronet.mobile.model.ConnectionProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ModeStatsTest {
    @Test fun idsUseTheFixedModeNamesAndMetrics() {
        assertEquals("normal:connect", ModeStats.id(ConnectionProfile.Normal, "connect"))
        assertEquals("gaming:ping", ModeStats.id(ConnectionProfile.Gaming, "ping"))
        assertEquals("legacy:stable", ModeStats.id(ConnectionProfile.Legacy, "stable"))
        assertEquals(setOf("normal", "fast", "gaming", "legacy"), ConnectionProfile.entries.map { ModeStats.mode(it) }.toSet())
    }

    @Test fun onlyALongEnoughSessionSaysAnythingAboutStability() {
        assertNull(ModeStats.stableSession(60_000, 0))
        assertEquals(true, ModeStats.stableSession(ModeStats.STABLE_AFTER_MS, 0))
        assertEquals(false, ModeStats.stableSession(ModeStats.STABLE_AFTER_MS * 3, 2))
    }

    @Test fun delaysAreRoundedBeforeTheyAreWritten() {
        val json = ModeStats.write(listOf(ModeStats.Fact("normal:connect", true, 3_437), ModeStats.Fact("normal:stable", false, null)))
        assertEquals(3_500, json.getJSONObject(0).getInt("ms"))
        assertTrue(!json.getJSONObject(1).has("ms"))
    }

    @Test fun factsSurviveAWriteAndRead() {
        val facts = listOf(ModeStats.Fact("fast:connect", true, 800), ModeStats.Fact("fast:stable", false, null))
        val back = ModeStats.read(ModeStats.write(facts).toString())
        assertEquals(listOf("fast:connect", "fast:stable"), back.map { it.id })
        assertEquals(listOf(true, false), back.map { it.ok })
        assertEquals(800, back[0].ms)
        assertNull(back[1].ms)
    }

    @Test fun garbageReadsAsNothing() {
        assertTrue(ModeStats.read("not json").isEmpty())
        assertTrue(ModeStats.read(null).isEmpty())
    }
}
