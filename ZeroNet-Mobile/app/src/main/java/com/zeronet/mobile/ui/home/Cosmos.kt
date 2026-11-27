package com.zeronet.mobile.ui.home

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * The sky around the globe, so it does not hang in a void: a few stars of every
 * brightness and a scatter of small white dots among them. It is kept quiet
 * on purpose: no sun, no moon, no coloured planets.
 *
 * Everything is a function of the clock; positions come from a fixed seed, so
 * the sky is the same every time and the tests can check it.
 */
@Composable
fun Cosmos(modifier: Modifier = Modifier, warp: Float = 0f) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val clock = rememberAmbientClock(!reduced)
    val dark = c.isDark
    androidx.compose.foundation.layout.Box(
        modifier
            .fillMaxSize()
            .drawWithCache {
                val sky = Sky.of(size.width, size.height)
                val unit = 1.dp.toPx()
                val ink = if (dark) Color.White else c.text
                onDrawBehind {
                    val t = if (reduced) 0f else clock.floatValue
                    drawSky(sky, unit, t, dark, ink, c.accent, warp)
                }
            },
    )
}

// -------------------------------------------------------------------- data

/** A star: where (0..1 of the screen), how big (in dp), how bright, when it twinkles, what colour. */
data class Star(val x: Float, val y: Float, val size: Float, val alpha: Float, val phase: Float, val warmth: Float)

/** A small white dot among the stars, with a slow shimmer. */
data class Exoplanet(val x: Float, val y: Float, val size: Float, val hue: Float, val phase: Float)

/** Where one of the white dots sits: a point on an arc around a distant centre, with a little drift. */
data class Planet(
    /** Arc size as a fraction of the screen width. */
    val orbit: Float,
    /** Where on the arc it sits, in radians, and how far it drifts either side. */
    val angle: Float,
    val drift: Float,
    /** Seconds for one drift cycle. */
    val period: Float,
    /** Its size, in dp; the dot is a fraction of it. */
    val radius: Float,
)

class Sky(val stars: List<Star>, val exoplanets: List<Exoplanet>, val width: Float, val height: Float) {
    companion object {
        /** A small fixed generator, so the sky never changes between runs or devices. */
        private class Rng(var state: Long) {
            fun next(): Float {
                state = state xor (state shl 13)
                state = state xor (state ushr 7)
                state = state xor (state shl 17)
                return ((state ushr 11) and 0xFFFFFF).toFloat() / 0x1000000.toFloat()
            }
        }

        fun of(width: Float, height: Float, stars: Int = 64, exoplanets: Int = 9): Sky {
            val rng = Rng(0x5EED_CAFE_1234L)
            val star = List(stars) {
                val bright = rng.next()
                Star(
                    x = rng.next(), y = rng.next() * rng.next().let { 0.35f + 0.65f * it },
                    size = 0.5f + 1.1f * bright * bright,
                    alpha = 0.25f + 0.65f * bright,
                    phase = rng.next() * 2f * PI.toFloat(),
                    warmth = rng.next(),
                )
            }
            val far = List(exoplanets) {
                Exoplanet(
                    x = rng.next(), y = rng.next() * 0.6f,
                    size = 1.4f + 1.2f * rng.next(),
                    hue = rng.next() * 360f,
                    phase = rng.next() * 2f * PI.toFloat(),
                )
            }
            return Sky(star, far, width, height)
        }

        /** Seven white dots, where the planets used to be. */
        val planets = listOf(
            Planet(0.20f, 0.55f, 0.10f, 44f, 1.5f),
            Planet(0.30f, 0.85f, 0.09f, 61f, 2.5f),
            Planet(0.44f, 0.40f, 0.08f, 83f, 2.1f),
            Planet(0.62f, 0.75f, 0.07f, 127f, 5.2f),
            Planet(0.82f, 0.50f, 0.06f, 151f, 4.4f),
            Planet(1.02f, 0.70f, 0.05f, 173f, 3.0f),
            Planet(1.22f, 0.45f, 0.05f, 199f, 3.0f),
        )
    }
}

/** The centre the arcs are measured from, off the top-left corner. */
internal fun sunCenter(width: Float, height: Float) = Offset(width * 0.02f, height * 0.015f)

/** Where a planet is on its (foreshortened) orbit at `seconds`. */
internal fun planetPosition(p: Planet, width: Float, height: Float, seconds: Float): Offset {
    val sun = sunCenter(width, height)
    val theta = p.angle + p.drift * sin(seconds / p.period * 2f * PI.toFloat())
    val rx = width * p.orbit
    return Offset(sun.x + cos(theta) * rx, sun.y + sin(theta) * rx * 0.62f)
}

// ----------------------------------------------------------------- drawing

private fun DrawScope.drawSky(sky: Sky, unit: Float, ms: Float, dark: Boolean, ink: Color, accent: Color, warp: Float) {
    val w = size.width
    val h = size.height
    val seconds = ms / 1000f
    val sun = sunCenter(w, h)

    // Stars, then the far planets.
    for (s in sky.stars) {
        val twinkle = 0.75f + 0.25f * sin(seconds * 1.3f + s.phase)
        val tint = lerp(ink, if (s.warmth > 0.7f) Color(0xFFFFD9A0) else if (s.warmth < 0.25f) Color(0xFFB9D0FF) else ink, if (dark) 0.6f else 0.3f)
        val center = Offset(s.x * w, s.y * h)
        drawCircle(tint.copy(alpha = (s.alpha * twinkle * if (dark) 1f else 0.7f).coerceIn(0f, 1f)), s.size * unit * 0.5f, center)
        if (warp > 0.02f) {
            // At speed a star is a streak, pointing away from where the camera is heading.
            val heading = Offset(w * 0.5f, h * 0.3f)
            val away = center - heading
            val len = away.getDistance().coerceAtLeast(1f)
            val streak = warp * (30f + 90f * s.size) * unit
            drawLine(tint.copy(alpha = (s.alpha * warp).coerceIn(0f, 0.9f)), center, Offset(center.x + away.x / len * streak, center.y + away.y / len * streak), 0.9f * unit, StrokeCap.Round)
        }
        if (s.size > 1.35f) {
            // The brightest ones get a small cross.
            val len = s.size * unit * 1.8f * twinkle
            val flare = tint.copy(alpha = 0.35f * twinkle)
            drawLine(flare, Offset(center.x - len, center.y), Offset(center.x + len, center.y), 0.5f * unit)
            drawLine(flare, Offset(center.x, center.y - len), Offset(center.x, center.y + len), 0.5f * unit)
        }
    }
    // What were planets are plain white dots now, as many as there were.
    for (e in sky.exoplanets) {
        val glow = 0.7f + 0.3f * sin(seconds * 0.7f + e.phase)
        drawCircle(ink.copy(alpha = 0.75f * glow), e.size * unit * 0.5f, Offset(e.x * w, e.y * h))
    }

    for (p in Sky.planets) {
        val at = planetPosition(p, w, h, 0f)
        drawCircle(ink.copy(alpha = 0.8f), (p.radius * 0.3f).coerceIn(0.6f, 1.4f) * unit, at)
    }

    // A shooting star now and then, across the upper sky.
    val cycle = 16f
    val phase = (seconds % cycle) / 1.1f
    if (phase in 0f..1f) {
        val from = Offset(w * 0.86f, h * 0.06f)
        val to = Offset(w * 0.52f, h * 0.20f)
        val head = Offset(from.x + (to.x - from.x) * phase, from.y + (to.y - from.y) * phase)
        val tail = Offset(from.x + (to.x - from.x) * (phase - 0.18f).coerceAtLeast(0f), from.y + (to.y - from.y) * (phase - 0.18f).coerceAtLeast(0f))
        drawLine(ink.copy(alpha = 0.7f * (1f - phase)), tail, head, 1.1f * unit, StrokeCap.Round)
    }
}

// ------------------------------------------------------------- orbits

/** Where something on a tilted, flattened orbit is: screen x and y, and depth (positive is in front). */
internal data class OrbitPoint(val x: Float, val y: Float, val z: Float)

internal fun orbitPoint(
    center: Offset, radius: Float, seconds: Float, periodSeconds: Float, phase: Float, flatten: Float, tiltDegrees: Float,
): OrbitPoint {
    val a = seconds / periodSeconds * 2f * PI.toFloat() + phase
    val ex = cos(a) * radius
    val ey = sin(a) * radius * flatten
    val tilt = tiltDegrees * PI.toFloat() / 180f
    val x = center.x + ex * cos(tilt) - ey * sin(tilt)
    val y = center.y + ex * sin(tilt) + ey * cos(tilt)
    return OrbitPoint(x, y, sin(a))
}
