package com.zeronet.mobile.ui.home

/**
 * Level of detail: how much of a planet is drawn for how big it looks.
 *
 * A planet that fills the screen shows everything; one that is far away, or
 * shrinking off into the distance, would only show noise and cost frames for
 * detail nobody can see. Detail fades in between two sizes instead of
 * switching, so nothing pops.
 *
 * Sizes are the planet's radius on screen in dp:
 *
 * * **coarse** (always): the disc, its shading, a cap, a couple of patches;
 * * **medium** from [MEDIUM_FROM] to [MEDIUM_FULL]: the big features, the
 *   glow and the orbits around Earth;
 * * **fine** from [FINE_FROM] to [FINE_FULL]: the graticule, every coastline,
 *   craters, canyons, volcanoes and cloud on Mars.
 */
object Lod {
    const val MEDIUM_FROM = 26f
    const val MEDIUM_FULL = 60f
    const val FINE_FROM = 66f
    const val FINE_FULL = 108f

    /** How much of each level to draw, `0..1`, and the size it was worked out from. */
    data class Detail(val radiusDp: Float, val medium: Float, val fine: Float) {
        /** Every how many coastline points to keep: all of them up close, fewer as it shrinks. */
        val coastStride: Int
            get() = when {
                radiusDp >= 96f -> 1
                radiusDp >= 60f -> 2
                radiusDp >= 30f -> 4
                else -> 8
            }

        /** Coastline rings shorter than this many points are dropped: at a distance they are specks. */
        val minRing: Int get() = if (coastStride >= 4) 12 else if (coastStride == 2) 6 else 0
    }

    private fun ramp(value: Float, from: Float, full: Float): Float {
        val t = ((value - from) / (full - from)).coerceIn(0f, 1f)
        return t * t * (3f - 2f * t)
    }

    fun of(radiusDp: Float): Detail =
        Detail(radiusDp, ramp(radiusDp, MEDIUM_FROM, MEDIUM_FULL), ramp(radiusDp, FINE_FROM, FINE_FULL))
}
