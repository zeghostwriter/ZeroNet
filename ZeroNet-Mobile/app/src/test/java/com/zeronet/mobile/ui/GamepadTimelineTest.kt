package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.effects.GamepadTimeline
import com.zeronet.mobile.ui.effects.Pad
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GamepadTimelineTest {
    private fun at(pad: Pad) = GamepadTimeline.presses.first { it.first == pad }.second.toFloat()

    @Test fun everyButtonIsPressedOnceInOrderBetweenTheLandingAndTheIgnition() {
        val order = GamepadTimeline.presses
        assertEquals(Pad.entries.toSet(), order.map { it.first }.toSet())
        assertEquals(Pad.entries.size, order.size)
        assertEquals(order.map { it.second }.sorted(), order.map { it.second })
        assertTrue(order.first().second > GamepadTimeline.DROP_IN_MS)
        assertTrue(order.last().second < GamepadTimeline.IGNITE_MS)
        assertTrue(GamepadTimeline.IGNITE_MS < GamepadTimeline.FADE_FROM_MS)
        assertTrue(GamepadTimeline.FADE_FROM_MS < GamepadTimeline.TOTAL_MS)
    }

    @Test fun aButtonGoesDownQuicklyIsHeldAndComesBackUp() {
        val at = at(Pad.A)
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at - 1f), 0f)
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at), 1e-6f)
        assertEquals(1f, GamepadTimeline.depth(Pad.A, at + 40f), 1e-6f)
        assertEquals(1f, GamepadTimeline.depth(Pad.A, at + 110f), 1e-6f)
        val rising = GamepadTimeline.depth(Pad.A, at + 160f)
        assertTrue(rising in 0.01f..0.99f)
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at + GamepadTimeline.PRESS_MS + 1f), 0f)
        // The button before it is already back up.
        assertEquals(0f, GamepadTimeline.depth(Pad.B, at + 80f), 0f)
    }

    @Test fun bothTriggersAreHeldTogetherUntilTheIgnition() {
        assertEquals(at(Pad.LeftTrigger), at(Pad.RightTrigger), 0f)
        val ignite = GamepadTimeline.IGNITE_MS.toFloat()
        for (trigger in listOf(Pad.LeftTrigger, Pad.RightTrigger)) {
            assertEquals(1f, GamepadTimeline.depth(trigger, ignite), 1e-6f)
            assertEquals(0f, GamepadTimeline.depth(trigger, ignite + 200f), 0f)
        }
    }

    @Test fun aPressLeavesSparksThatOutliveIt() {
        val at = at(Pad.X)
        val over = GamepadTimeline.SPARK_MS.toFloat()
        assertEquals(-1f, GamepadTimeline.phase(Pad.X, at - 1f, over), 0f)
        assertEquals(0f, GamepadTimeline.phase(Pad.X, at, over), 1e-6f)
        assertEquals(0.5f, GamepadTimeline.phase(Pad.X, at + over / 2f, over), 1e-6f)
        assertEquals(-1f, GamepadTimeline.phase(Pad.X, at + over + 1f, over), 0f)
        assertTrue(GamepadTimeline.SPARK_MS > GamepadTimeline.PRESS_MS)
    }

    @Test fun eachPressIsReportedExactlyOnceAsTheClockPassesIt() {
        var last = 0f
        val seen = mutableListOf<Pad>()
        var ms = 0f
        while (ms < GamepadTimeline.TOTAL_MS) {
            ms += 16f
            seen += GamepadTimeline.newPresses(last, ms)
            last = ms
        }
        assertEquals(GamepadTimeline.presses.map { it.first }, seen)
    }

    @Test fun theChargeClimbsWithEachPressAndIsFullAtTheIgnition() {
        assertEquals(0f, GamepadTimeline.charge(GamepadTimeline.DROP_IN_MS.toFloat()), 0f)
        var before = 0f
        var ms = 0f
        while (ms <= GamepadTimeline.TOTAL_MS) {
            val now = GamepadTimeline.charge(ms)
            assertTrue("the charge fell at $ms", now >= before)
            before = now
            ms += 16f
        }
        assertEquals(1f, GamepadTimeline.charge(GamepadTimeline.IGNITE_MS.toFloat()), 1e-6f)
        // Half way through the presses the ring is about half lit.
        val middle = GamepadTimeline.presses[GamepadTimeline.presses.size / 2].second.toFloat()
        assertTrue(GamepadTimeline.charge(middle) in 0.35f..0.65f)
        assertEquals(0f, GamepadTimeline.lit(3, GamepadTimeline.presses[3].second - 1f), 0f)
        assertEquals(1f, GamepadTimeline.lit(3, GamepadTimeline.presses[3].second + 200f), 0f)
    }

    @Test fun theIgnitionJoltsOnceAndDiesAway() {
        val ignite = GamepadTimeline.IGNITE_MS.toFloat()
        assertEquals(0f, GamepadTimeline.kick(ignite - 1f), 0f)
        assertEquals(1f, GamepadTimeline.kick(ignite), 1e-6f)
        assertTrue(GamepadTimeline.kick(ignite + 250f) in 0.01f..0.99f)
        assertEquals(0f, GamepadTimeline.kick(ignite + 500f), 1e-6f)
        // The streaks rush while it arrives and after the ignition, and are calm in between.
        assertEquals(1f, GamepadTimeline.rush(0f), 1e-6f)
        assertEquals(0f, GamepadTimeline.rush(1500f), 0f)
        assertEquals(1f, GamepadTimeline.rush(ignite), 1e-6f)
        assertEquals(0f, GamepadTimeline.rush(GamepadTimeline.TOTAL_MS.toFloat()), 0f)
    }

    @Test fun theSceneFadesInAndOutAndTheControllerFliesIntoPlace() {
        assertEquals(0f, GamepadTimeline.opacity(0f), 0f)
        assertEquals(1f, GamepadTimeline.opacity(1500f), 0f)
        assertEquals(0f, GamepadTimeline.opacity(GamepadTimeline.TOTAL_MS.toFloat()), 1e-6f)
        assertEquals(0f, GamepadTimeline.drop(0f), 1e-6f)
        assertEquals(1f, GamepadTimeline.drop(GamepadTimeline.DROP_IN_MS.toFloat()), 1e-6f)
        // A little overshoot on the way.
        assertTrue((0..52).map { GamepadTimeline.drop(it * 10f) }.max() > 1f)
        // The still picture for reduced motion is fully lit, settled and readable.
        val still = GamepadTimeline.STILL_MS
        assertEquals(1f, GamepadTimeline.opacity(still), 0f)
        assertEquals(1f, GamepadTimeline.charge(still), 0f)
        assertEquals(0f, GamepadTimeline.kick(still), 0f)
    }
}
