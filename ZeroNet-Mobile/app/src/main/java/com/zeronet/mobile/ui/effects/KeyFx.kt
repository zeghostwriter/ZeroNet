package com.zeronet.mobile.ui.effects

/**
 * The key-decryption effect: a row of glyphs that churns like cipher text and
 * then settles, left to right, into the real characters.
 *
 * It is the same pure function as `zeronet-tui/src/keyfx.rs`, with the same
 * mixing and the same tables, so both apps draw the same sequence; the tests
 * check the same fixed outputs. Most of the churn is hex digits and marks from
 * a few Unicode blocks; [WIDE_PERCENT] percent is Chinese characters, which
 * are two columns wide, so one takes the place of two cells.
 */
object KeyFx {
    const val WIDE_PERCENT = 4UL
    const val STEP_TICKS = 2L
    const val REVEAL_TICKS_PER_CELL = 1L

    const val WIDE = "密钥解码安全加锁数据匙令牌破译密"
    const val HEX = "0123456789ABCDEF"
    const val MARKS = "αβγδλμπσφψω∑∏∂∇≈≠∞⊕⊗◆◇▲▽●○■□░▒▓¤§¶"

    enum class Kind { Gap, Locked, Front, Churn, Wide }

    /** One drawn cell. A [Kind.Wide] cell takes two columns. */
    data class Cell(val ch: Char, val kind: Kind) {
        val width: Int get() = if (kind == Kind.Wide) 2 else 1
    }

    /** Splitmix64 finaliser: the same glyph on every platform. */
    fun mix(seed: ULong, index: ULong, step: ULong): ULong {
        var z = seed xor (index * 0x9E3779B97F4A7C15uL) xor (step * 0xC2B2AE3D27D4EB4FuL)
        z += 0x9E3779B97F4A7C15uL
        z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9uL
        z = (z xor (z shr 27)) * 0x94D049BB133111EBuL
        return z xor (z shr 31)
    }

    private fun churn(seed: ULong, index: Int, tick: Long, allowWide: Boolean): Pair<Char, Boolean> {
        val h = mix(seed, index.toULong(), (tick / STEP_TICKS).toULong())
        if (allowWide && (h shr 40) % 100UL < WIDE_PERCENT) {
            return WIDE[((h shr 8) % WIDE.length.toULong()).toInt()] to true
        }
        val pick = h shr 8
        return if ((h shr 48) % 100UL < 62UL) {
            HEX[(pick % HEX.length.toULong()).toInt()] to false
        } else {
            MARKS[(pick % MARKS.length.toULong()).toInt()] to false
        }
    }

    /**
     * The row at [tick]. [template] is the row as it will end up: a space is a
     * gap that never churns, anything else settles on that character once the
     * front has passed it. [locked] is how many cells have settled, or null
     * while nothing is known yet; the cell at [locked] is the front.
     */
    fun frame(template: String, tick: Long, locked: Int?, seed: ULong): List<Cell> {
        val front = locked?.let { from -> (from until template.length).firstOrNull { template[it] != ' ' } }
        val settled = locked ?: 0
        val cells = ArrayList<Cell>(template.length)
        var index = 0
        while (index < template.length) {
            val real = template[index]
            when {
                real == ' ' -> { cells += Cell(' ', Kind.Gap); index += 1 }
                index < settled -> { cells += Cell(real, Kind.Locked); index += 1 }
                index == front -> {
                    cells += Cell(churn(seed, index, tick, false).first, Kind.Front)
                    index += 1
                }
                else -> {
                    val room = template.getOrNull(index + 1).let { it != null && it != ' ' }
                    val (ch, wide) = churn(seed, index, tick, room)
                    cells += Cell(ch, if (wide) Kind.Wide else Kind.Churn)
                    index += if (wide) 2 else 1
                }
            }
        }
        return cells
    }

    /** How many cells have settled [elapsed] ticks after the reveal began, out of [count]. */
    fun settled(elapsed: Long, count: Int): Int = (elapsed / REVEAL_TICKS_PER_CELL).coerceAtMost(count.toLong()).toInt()

    /** Ticks a reveal of [count] cells takes, plus a beat for the last one. */
    fun revealDuration(count: Int): Long = count * REVEAL_TICKS_PER_CELL + 6

    fun text(cells: List<Cell>): String = cells.joinToString("") { it.ch.toString() }
}
