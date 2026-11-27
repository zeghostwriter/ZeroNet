package com.zeronet.mobile.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.home.rememberAmbientClock
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/** Seconds between one strike and the next. */
private const val STRIKE_EVERY = 3.4f

/** The bolt in a 24 by 24 box: jagged, with a bright inner edge and two forks. */
private val MAIN = listOf(
    15.2f to 1.0f, 8.6f to 10.4f, 12.0f to 10.4f, 7.2f to 15.6f, 10.6f to 15.6f,
    8.0f to 23.0f, 18.8f to 10.2f, 14.2f to 10.2f, 17.6f to 1.0f,
)
private val INNER = listOf(
    15.0f to 4.0f, 11.2f to 9.6f, 13.4f to 9.6f, 10.0f to 14.2f, 12.2f to 14.2f, 10.2f to 19.0f, 16.0f to 11.4f, 12.6f to 11.4f, 15.6f to 4.0f,
)
private val FORKS = listOf(
    listOf(8.6f to 10.4f, 5.6f to 9.2f, 4.4f to 6.6f),
    listOf(18.8f to 10.2f, 20.6f to 12.4f, 21.4f to 15.4f),
    listOf(7.2f to 15.6f, 4.4f to 16.8f, 3.6f to 19.6f),
)

/**
 * The lightning bolt for "fastest": a detailed bolt with forks, glowing
 * inside a round badge. Every few seconds it strikes: a flicker, a ring of
 * light, and sparks thrown off. Under reduced motion it is the bolt at rest.
 */
@Composable
fun LightningBadge(
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
    tint: Color = ZeroTheme.colors.accent,
    alive: Boolean = true,
) {
    val reduced = LocalReducedMotion.current
    val clock = rememberAmbientClock(alive && !reduced)
    Box(
        modifier.size(size).clip(CircleShape).background(tint.copy(alpha = 0.16f)),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(size).clearAndSetSemantics { }) {
            val seconds = if (alive && !reduced) clock.floatValue / 1000f else 0f
            drawStrike(tint, strike(seconds), seconds)
        }
    }
}

/**
 * How far into a strike it is, `0..1` (a strike lasts a second), or `-1` between strikes.
 */
internal fun strike(seconds: Float): Float {
    val into = seconds % STRIKE_EVERY
    return if (into < 1f) into else -1f
}

/**
 * The flicker of a strike: bright, dark, bright, dim, bright, then fading.
 * `0..1` at strike time [s], and a steady glow (`0.25`) between strikes.
 */
internal fun flash(s: Float): Float = when {
    s < 0f -> 0.25f
    s < 0.06f -> 1f
    s < 0.11f -> 0.15f
    s < 0.20f -> 1f
    s < 0.26f -> 0.35f
    s < 0.36f -> 0.95f
    else -> 0.95f * (1f - ((s - 0.36f) / 0.64f)).coerceIn(0f, 1f) + 0.25f * ((s - 0.36f) / 0.64f).coerceIn(0f, 1f)
}

private fun DrawScope.bolt(points: List<Pair<Float, Float>>, scale: Float, origin: Offset): Path = Path().apply {
    points.forEachIndexed { i, (x, y) ->
        val p = Offset(origin.x + x * scale, origin.y + y * scale)
        if (i == 0) moveTo(p.x, p.y) else lineTo(p.x, p.y)
    }
    close()
}

private fun DrawScope.drawStrike(tint: Color, s: Float, seconds: Float) {
    val box = size.minDimension * 0.62f
    val scale = box / 24f
    val origin = Offset((size.width - box) / 2f, (size.height - box) / 2f)
    val level = flash(s)
    val hot = lerp(tint, Color.White, 0.75f)
    val center = Offset(size.width / 2f, size.height / 2f)

    // The glow behind the bolt.
    drawCircle(
        Brush.radialGradient(
            listOf(tint.copy(alpha = 0.55f * level), Color.Transparent),
            center = center, radius = size.minDimension * (0.42f + 0.10f * level),
        ),
        radius = size.minDimension * 0.52f, center = center,
    )

    // The ring of light that leaves the bolt when it strikes.
    if (s in 0f..0.6f) {
        val grow = s / 0.6f
        drawCircle(
            tint.copy(alpha = 0.55f * (1f - grow)),
            radius = size.minDimension * (0.18f + 0.34f * grow), center = center,
            style = Stroke(size.minDimension * 0.035f * (1f - grow) + 1f),
        )
    }

    // The forks, drawn as thin crackles that come and go with the flash.
    val fork = tint.copy(alpha = (0.35f + 0.6f * level).coerceIn(0f, 1f))
    for (line in FORKS) {
        val path = Path()
        line.forEachIndexed { i, (x, y) ->
            val p = Offset(origin.x + x * scale, origin.y + y * scale)
            if (i == 0) path.moveTo(p.x, p.y) else path.lineTo(p.x, p.y)
        }
        drawPath(path, fork, style = Stroke(scale * 0.55f, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }

    // The bolt: a soft wide outline, the body in the badge colour, the bright inner edge.
    val body = bolt(MAIN, scale, origin)
    drawPath(body, tint.copy(alpha = 0.35f * level), style = Stroke(scale * 2.4f, join = StrokeJoin.Round))
    drawPath(
        body,
        Brush.verticalGradient(
            0f to lerp(tint, Color.White, 0.35f * level),
            1f to tint,
            startY = origin.y, endY = origin.y + box,
        ),
    )
    drawPath(bolt(INNER, scale, origin), hot.copy(alpha = (0.45f + 0.5f * level).coerceIn(0f, 1f)))
    drawPath(body, hot.copy(alpha = 0.9f * level), style = Stroke(scale * 0.5f, join = StrokeJoin.Round))

    // Sparks thrown off by a strike.
    if (s in 0.05f..0.7f) {
        val t = (s - 0.05f) / 0.65f
        for (k in 0 until 7) {
            val angle = k * 2f * PI.toFloat() / 7f + 0.4f
            val reach = size.minDimension * (0.22f + 0.30f * t) * (0.8f + 0.2f * ((k * 37) % 5) / 4f)
            val at = Offset(center.x + cos(angle) * reach, center.y + sin(angle) * reach)
            drawCircle(hot.copy(alpha = (1f - t) * 0.9f), size.minDimension * 0.022f * (1f - t * 0.5f), at)
        }
    }
    // Between strikes the glow breathes a little.
    if (s < 0f) {
        val breath = 0.5f + 0.5f * sin(seconds * 2.2f)
        drawCircle(hot.copy(alpha = 0.06f * breath), size.minDimension * 0.30f, center)
    }
}
