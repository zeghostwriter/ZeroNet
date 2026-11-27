package com.zeronet.mobile.ui.effects

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * A small picture that stands for a WARP account's fingerprint: six by four
 * mirrored blocks and a colour. The fingerprint is a string nobody compares by
 * eye; this tells two accounts apart at a glance, and an account always looks
 * the same.
 *
 * The same pure function as `zero-discovery/src/glyph.rs`; the tests on both
 * sides check the same fixed outputs.
 */
object Glyph {
    const val COLUMNS = 6
    const val ROWS = 4

    /** [rows] has bit `c` of row `r` set when the block in column `c` is filled; the picture is mirrored. */
    data class Picture(val rows: IntArray, val hue: Int) {
        fun filled(column: Int, row: Int): Boolean =
            column in 0 until COLUMNS && row in 0 until ROWS && (rows[row] shr column) and 1 == 1

        override fun equals(other: Any?) = other is Picture && rows.contentEquals(other.rows) && hue == other.hue
        override fun hashCode() = rows.contentHashCode() * 31 + hue
    }

    /** The picture for a fingerprint, or null when it is not one (fewer than eight hex digits). */
    fun of(fingerprint: String): Picture? {
        val digits = fingerprint.mapNotNull { Character.digit(it, 16).takeIf { d -> d >= 0 } }
        if (digits.size < 8) return null
        fun word(at: Int) = digits.subList(at, at + 4).fold(0) { acc, d -> acc shl 4 or d }
        var cells = word(0) and 0xFFF
        // Every fingerprint gets a mark: a blank picture reads as missing.
        if (cells == 0) cells = (1 shl 5) or (1 shl 8)
        val rows = IntArray(ROWS)
        for (r in 0 until ROWS) {
            for (c in 0 until COLUMNS / 2) {
                if ((cells shr (r * 3 + c)) and 1 == 1) rows[r] = rows[r] or (1 shl c) or (1 shl (COLUMNS - 1 - c))
            }
        }
        return Picture(rows, word(4) % 360)
    }

    /** The colour for a hue: HSL at s = 0.62, l = 0.58, which reads on light and dark. */
    fun rgb(hue: Int): Triple<Int, Int, Int> {
        val s = 0.62f
        val l = 0.58f
        val c = (1f - abs(2f * l - 1f)) * s
        val h = (hue % 360) / 60f
        val x = c * (1f - abs(h % 2f - 1f))
        val (r, g, b) = when (h.toInt()) {
            0 -> Triple(c, x, 0f)
            1 -> Triple(x, c, 0f)
            2 -> Triple(0f, c, x)
            3 -> Triple(0f, x, c)
            4 -> Triple(x, 0f, c)
            else -> Triple(c, 0f, x)
        }
        val m = l - c / 2f
        fun byte(v: Float) = ((v + m).coerceIn(0f, 1f) * 255f).roundToInt()
        return Triple(byte(r), byte(g), byte(b))
    }

    fun color(hue: Int): Color = rgb(hue).let { (r, g, b) -> Color(r, g, b) }
}

/**
 * The picture in a round badge the size of a flag badge, so a WARP account
 * sits in a list where a country's flag would.
 */
@Composable
fun GlyphBadge(fingerprint: String, modifier: Modifier = Modifier, size: Dp = 40.dp) {
    val c = ZeroTheme.colors
    val picture = remember(fingerprint) { Glyph.of(fingerprint) } ?: return
    val color = remember(picture) { Glyph.color(picture.hue) }
    Box(
        modifier.size(size).clip(CircleShape).background(c.surfaceHi),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(size * 0.56f)) {
            val cell = this.size.width / Glyph.COLUMNS
            val gap = cell * 0.14f
            val corner = CornerRadius(cell * 0.28f)
            val top = (this.size.height - cell * Glyph.ROWS) / 2f
            for (row in 0 until Glyph.ROWS) {
                for (column in 0 until Glyph.COLUMNS) {
                    if (picture.filled(column, row)) {
                        drawRoundRect(
                            color,
                            topLeft = Offset(column * cell + gap / 2f, top + row * cell + gap / 2f),
                            size = Size(cell - gap, cell - gap),
                            cornerRadius = corner,
                        )
                    }
                }
            }
        }
    }
}
