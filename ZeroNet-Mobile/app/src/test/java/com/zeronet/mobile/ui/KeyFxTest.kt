package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.effects.KeyFx
import com.zeronet.mobile.ui.effects.KeyFx.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyFxTest {
    private val template = "3FA9 C0D1 7B42 E8A5"

    private fun columns(cells: List<KeyFx.Cell>) = cells.sumOf { it.width }

    /** The same fixed outputs the terminal app's tests check. */
    @Test fun sharedTestVectors() {
        assertEquals(0x1915f685d2b0e282uL, KeyFx.mix(1uL, 2uL, 3uL))
        assertEquals("1░π9 6C4C ▓05B 2F○B", KeyFx.text(KeyFx.frame(template, 6, null, 42uL)))
        assertEquals("3FA9 C0∂F 3ψ76 αφπC", KeyFx.text(KeyFx.frame(template, 31, 7, 42uL)))
    }

    @Test fun aRowKeepsItsWidthHoweverManyWideCharactersItDraws() {
        for (tick in 0L until 400L) {
            assertEquals("tick $tick", template.length, columns(KeyFx.frame(template, tick, null, 7uL)))
        }
    }

    @Test fun gapsNeverChurnAndSettledCellsShowTheRealCharacters() {
        val cells = KeyFx.frame(template, 40, 9, 7uL)
        assertTrue(KeyFx.text(cells).startsWith("3FA9 C0D1"))
        assertEquals(Kind.Gap, cells[4].kind)
        assertEquals(Kind.Front, cells[10].kind)
        assertTrue(cells.drop(11).all { it.kind == Kind.Churn || it.kind == Kind.Wide || it.kind == Kind.Gap })
        val done = KeyFx.frame(template, 99, template.length, 7uL)
        assertEquals(template, KeyFx.text(done))
        assertTrue(done.all { it.kind == Kind.Locked || it.kind == Kind.Gap })
    }

    @Test fun churnMovesWithTimeAndSeed() {
        val a = KeyFx.text(KeyFx.frame(template, 10, null, 1uL))
        assertEquals(a, KeyFx.text(KeyFx.frame(template, 11, null, 1uL)))
        assertTrue(a != KeyFx.text(KeyFx.frame(template, 12, null, 1uL)))
        assertTrue(a != KeyFx.text(KeyFx.frame(template, 10, null, 2uL)))
    }

    @Test fun aboutFourPercentOfTheChurnIsChinese() {
        val row = "A".repeat(60)
        var wide = 0
        var all = 0
        for (tick in 0L until 6000L step KeyFx.STEP_TICKS) {
            for (cell in KeyFx.frame(row, tick, null, 99uL)) {
                all++
                if (cell.kind == Kind.Wide) {
                    wide++
                    assertTrue(cell.ch in KeyFx.WIDE)
                }
            }
        }
        val share = wide * 100.0 / all
        assertTrue("$share%", share in 3.0..5.0)
    }

    @Test fun theRevealTakesAKnownTime() {
        assertEquals(0, KeyFx.settled(0, 32))
        assertEquals(10, KeyFx.settled(10, 32))
        assertEquals(32, KeyFx.settled(1000, 32))
        assertTrue(KeyFx.revealDuration(32) > 32)
    }
}
