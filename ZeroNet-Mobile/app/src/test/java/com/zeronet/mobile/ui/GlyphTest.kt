package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.effects.Glyph
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GlyphTest {
    private val fingerprint = "3FA9 C0D1 7B42 E8A5 0F1E 2D3C 4B5A 6978"

    /** The same fixed outputs `zero-discovery/src/glyph.rs` checks. */
    @Test fun sharedTestVectors() {
        val glyph = Glyph.of(fingerprint)!!
        assertArrayEquals(intArrayOf(0b100001, 0b101101, 0b011110, 0b111111), glyph.rows)
        assertEquals(41, glyph.hue)
        assertEquals(Triple(214, 172, 81), Glyph.rgb(41))
    }

    @Test fun sameFingerprintSamePictureOtherFingerprintOtherPicture() {
        val a = Glyph.of(fingerprint)!!
        assertEquals(a, Glyph.of(fingerprint.replace(" ", ""))!!)
        assertEquals(a, Glyph.of(fingerprint.lowercase())!!)
        assertNotEquals(a, Glyph.of("3FA8 C0D1 7B42 E8A5")!!)
        assertNotEquals(a, Glyph.of("3FA9 C0D2 7B42 E8A5")!!)
    }

    @Test fun theImageIsMirroredAndNeverBlank() {
        for (seed in 0 until 200) {
            val text = "%04X %04X".format((seed * 2654435761L shr 16).toInt() and 0xFFFF, seed * 977 and 0xFFFF)
            val glyph = Glyph.of(text)!!
            for (row in 0 until Glyph.ROWS) for (column in 0 until Glyph.COLUMNS) {
                assertEquals(text, glyph.filled(column, row), glyph.filled(Glyph.COLUMNS - 1 - column, row))
            }
        }
        assertTrue(Glyph.of("0000 0000")!!.rows.any { it != 0 })
    }

    @Test fun notAFingerprintGivesNothing() {
        assertNull(Glyph.of(""))
        assertNull(Glyph.of("zz"))
        assertNull(Glyph.of("3FA"))
        assertNotNull(Glyph.of("3FA9 C0D1"))
    }

    @Test fun everyHueGivesAColourThatIsNeitherGreyNorExtreme() {
        for (hue in 0 until 360) {
            val (r, g, b) = Glyph.rgb(hue)
            val high = maxOf(r, g, b)
            val low = minOf(r, g, b)
            assertTrue("hue $hue is grey", high - low > 40)
            assertTrue("hue $hue: ($r, $g, $b)", high > 120 && low < 200)
        }
    }
}
