package com.zeronet.mobile.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.spring
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.remember
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * The highlight behind the chosen button: a blob that is stuck to the button
 * it left until it lets go, stretches toward the next one, and lands on it
 * with a bounce.
 *
 * Two edges move on their own springs. The leading edge is stiff and
 * underdamped, so it races ahead and overshoots; the trailing edge is soft
 * and stays behind. Between them the body thins in the middle, like something
 * sticky being pulled apart, and squashes a little as it stretches. At rest
 * it is an ordinary pill.
 *
 * Positions are in button units (0 is the first button, 1 the next, ...), so
 * one blob serves a tab bar, a segmented control and a row of cards.
 */
@Stable
class BlobMotion(initial: Float) {
    val lead = Animatable(initial)
    val trail = Animatable(initial)

    /** Where the blob's left and right ends are, in button units, before it is sized to the buttons. */
    val from: Float get() = min(lead.value, trail.value)
    val to: Float get() = max(lead.value, trail.value)

    /** How far apart the edges are, in buttons: 0 at rest. */
    val stretch: Float get() = abs(lead.value - trail.value)

    suspend fun moveTo(index: Float, animate: Boolean) {
        if (!animate) {
            lead.snapTo(index)
            trail.snapTo(index)
            return
        }
        kotlinx.coroutines.coroutineScope {
            launch { lead.animateTo(index, spring(dampingRatio = 0.5f, stiffness = ZeroMotion.k(520f))) }
            launch { trail.animateTo(index, spring(dampingRatio = 0.62f, stiffness = ZeroMotion.k(190f))) }
        }
    }
}

/** A [BlobMotion] that follows [index]. */
@Composable
fun rememberBlob(index: Int): BlobMotion {
    val reduced = LocalReducedMotion.current
    val blob = remember { BlobMotion(index.toFloat()) }
    LaunchedEffect(index, reduced) { blob.moveTo(index.toFloat(), animate = !reduced) }
    return blob
}

/**
 * Draw the blob over a row of [count] equal buttons that fill [area], with
 * [gap] between them. [mirrored] runs the row right to left.
 */
fun DrawScope.drawBlob(
    blob: BlobMotion,
    count: Int,
    area: Rect,
    gap: Float,
    color: Color,
    mirrored: Boolean = false,
    outline: Color? = null,
    corner: Float = Float.MAX_VALUE,
) {
    if (count <= 0) return
    val cell = (area.width - gap * (count - 1)) / count
    val step = cell + gap
    fun left(unit: Float) = if (mirrored) area.right - cell - unit * step else area.left + unit * step
    val a = left(blob.from)
    val b = left(blob.to)
    val x0 = min(a, b)
    val x1 = max(a, b) + cell
    val stretch = blob.stretch.coerceIn(0f, 2.5f)
    val path = blobPath(x0, x1, area.top, area.bottom, stretch, corner)
    drawPath(path, color)
    outline?.let { drawPath(path, it, style = Stroke(1.5.dp.toPx())) }
}


/**
 * The body: a pill from [x0] to [x1] whose top and bottom edges dip toward
 * each other in the middle by an amount that grows with [stretch], and whose
 * height shrinks a little while it stretches.
 */
internal fun blobPath(x0: Float, x1: Float, top: Float, bottom: Float, stretch: Float, corner: Float = Float.MAX_VALUE): Path {
    val squash = 0.10f * min(stretch, 1f)
    val h = bottom - top
    val inset = h * squash / 2f
    val t = top + inset
    val bo = bottom - inset
    val width = x1 - x0
    // The corner is as round as asked, and never more than a pill allows.
    val rc = min(min(corner, (bo - t) / 2f), width / 2f)
    val pinch = (bo - t) * 0.34f * min(stretch / 1.2f, 1f)
    val run = max(0f, width - 2 * rc)
    return Path().apply {
        moveTo(x0 + rc, t)
        cubicTo(x0 + rc + run * 0.3f, t + pinch, x1 - rc - run * 0.3f, t + pinch, x1 - rc, t)
        arcTo(Rect(x1 - 2 * rc, t, x1, t + 2 * rc), -90f, 90f, false)
        lineTo(x1, bo - rc)
        arcTo(Rect(x1 - 2 * rc, bo - 2 * rc, x1, bo), 0f, 90f, false)
        cubicTo(x1 - rc - run * 0.3f, bo - pinch, x0 + rc + run * 0.3f, bo - pinch, x0 + rc, bo)
        arcTo(Rect(x0, bo - 2 * rc, x0 + 2 * rc, bo), 90f, 90f, false)
        lineTo(x0, t + rc)
        arcTo(Rect(x0, t, x0 + 2 * rc, t + 2 * rc), 180f, 90f, false)
        close()
    }
}
