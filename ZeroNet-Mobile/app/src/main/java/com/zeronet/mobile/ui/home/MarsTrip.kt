package com.zeronet.mobile.ui.home

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.lifecycle.repeatOnLifecycle
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.lerp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * A screen left alone for a long while makes a visit to Mars: the camera
 * races there, stays a while, and comes home.
 *
 * The timeline is a pure function of the time since the trip began, so a frame
 * can be tested; any touch ends the visit early and the camera turns back.
 */
object MarsTrip {
    /** How long the app sits untouched on the screen before it goes: 4 min 26 s 26 ms. */
    const val IDLE_MS = 266_026L

    /** Each flight, and the stay between them. */
    const val FLIGHT_MS = 1_400L
    const val STAY_MS = 23_000L
    const val TOTAL_MS = FLIGHT_MS + STAY_MS + FLIGHT_MS

    /** What is on screen: how big Earth and Mars are (`0..1`), the streaking of the stars, and whether the words show. */
    data class Frame(val earth: Float, val mars: Float, val warp: Float, val words: Boolean)

    private fun smooth(x: Float): Float {
        val t = x.coerceIn(0f, 1f)
        return t * t * (3f - 2f * t)
    }

    /** The frame [elapsedMs] into the trip, or null when it is over. */
    fun at(elapsedMs: Long): Frame? {
        if (elapsedMs < 0 || elapsedMs >= TOTAL_MS) return null
        val words = elapsedMs >= FLIGHT_MS / 2 && elapsedMs < FLIGHT_MS + STAY_MS + FLIGHT_MS / 2
        return when {
            elapsedMs < FLIGHT_MS -> {
                val t = elapsedMs.toFloat() / FLIGHT_MS
                Frame(earth = 1f - smooth(t / 0.5f), mars = smooth((t - 0.5f) / 0.5f), warp = bell(t), words = words)
            }
            elapsedMs < FLIGHT_MS + STAY_MS -> Frame(0f, 1f, 0f, words)
            else -> {
                val t = (elapsedMs - FLIGHT_MS - STAY_MS).toFloat() / FLIGHT_MS
                Frame(earth = smooth((t - 0.5f) / 0.5f), mars = 1f - smooth(t / 0.5f), warp = bell(t), words = words)
            }
        }
    }

    /** `0` at both ends, `1` in the middle: the streaking of the stars. */
    private fun bell(t: Float): Float = sin(PI.toFloat() * t.coerceIn(0f, 1f)).let { it * it }

    /**
     * Where the trip should carry on from when the screen is touched at
     * [elapsedMs]: from Mars, straight into the flight home; on the way there,
     * the same distance back; already on the way home, unchanged.
     */
    fun afterTouch(elapsedMs: Long): Long = when {
        elapsedMs < 0 -> elapsedMs
        elapsedMs < FLIGHT_MS -> FLIGHT_MS + STAY_MS + (FLIGHT_MS - elapsedMs)
        elapsedMs < FLIGHT_MS + STAY_MS -> FLIGHT_MS + STAY_MS
        else -> elapsedMs
    }
}

// ----------------------------------------------------------------- drawing

/** Lines streaming outward from the middle: the stars going by at speed. */
fun DrawScope.drawWarp(center: Offset, radius: Float, warp: Float, tint: Color) {
    if (warp <= 0.01f) return
    val unit = radius / 134f
    for (k in 0 until 30) {
        val angle = k * 2f * PI.toFloat() / 30f + ((k * 37) % 11) * 0.03f
        val start = radius * (1.05f + 0.9f * ((k * 13) % 7) / 7f)
        val length = radius * (0.5f + 2.2f * ((k * 29) % 5) / 5f) * warp
        val from = Offset(center.x + cos(angle) * start, center.y + sin(angle) * start)
        val to = Offset(center.x + cos(angle) * (start + length), center.y + sin(angle) * (start + length))
        drawLine(tint.copy(alpha = 0.4f * warp), from, to, (1.1f + (k % 3) * 0.5f) * unit, StrokeCap.Round)
    }
}

/** Phobos, quick and close, and Deimos, slow and far: two small grey lumps. */
internal fun DrawScope.marsMoons(center: Offset, r: Float, seconds: Float, front: Boolean) {
    for ((radiusFactor, period, phase, size, flatten) in listOf(
        listOf(1.34f, 5.5f, 0.6f, 0.028f, 0.24f), listOf(1.66f, 17f, 2.8f, 0.02f, 0.30f),
    )) {
        val p = orbitPoint(center, r * radiusFactor, seconds, period, phase, flatten, -10f)
        if ((p.z >= 0f) != front) continue
        val at = Offset(p.x, p.y)
        if (p.z < 0f && (at - center).getDistance() < r) continue
        val s = r * size
        drawOval(Color(0xFF8C8580), Offset(at.x - s * 1.2f, at.y - s * 0.9f), Size(s * 2.4f, s * 1.8f))
        drawOval(Color(0xFFC9C3BC).copy(alpha = 0.7f), Offset(at.x - s * 0.9f, at.y - s * 0.8f), Size(s * 1.2f, s * 0.8f))
    }
}


// ------------------------------------------------------------- the clock

/** The visit as a screen keeps it: the frame to draw now, and a modifier that listens for touches. */
@androidx.compose.runtime.Stable
class MarsTripState internal constructor(
    private val frameState: androidx.compose.runtime.State<MarsTrip.Frame?>,
    val touchListener: androidx.compose.ui.Modifier,
) {
    val frame: MarsTrip.Frame? get() = frameState.value
}

/**
 * Watches for the screen to be left alone for [MarsTrip.IDLE_MS] while the app
 * is in front, then runs the visit. Touches restart the wait, or turn a visit
 * for home. Leaving the app and coming back starts the wait again.
 */
@androidx.compose.runtime.Composable
fun rememberMarsTrip(): MarsTripState {
    val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
    val lastInput = androidx.compose.runtime.remember { androidx.compose.runtime.mutableLongStateOf(android.os.SystemClock.uptimeMillis()) }
    val startedAt = androidx.compose.runtime.remember { androidx.compose.runtime.mutableLongStateOf(0L) }
    val frame = androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<MarsTrip.Frame?>(null) }

    androidx.compose.runtime.LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.RESUMED) {
            lastInput.longValue = android.os.SystemClock.uptimeMillis()
            startedAt.longValue = 0L
            frame.value = null
            while (true) {
                val now = android.os.SystemClock.uptimeMillis()
                if (startedAt.longValue == 0L) {
                    val left = MarsTrip.IDLE_MS - (now - lastInput.longValue)
                    if (left > 0) {
                        kotlinx.coroutines.delay(left)
                        continue
                    }
                    startedAt.longValue = now
                }
                val elapsed = now - startedAt.longValue
                val next = MarsTrip.at(elapsed)
                if (next == null) {
                    // Home again: the wait starts over.
                    startedAt.longValue = 0L
                    frame.value = null
                    lastInput.longValue = now
                } else {
                    frame.value = next
                    androidx.compose.runtime.withFrameNanos { }
                }
            }
        }
    }

    val touch = androidx.compose.ui.Modifier.pointerInput(Unit) {
        awaitPointerEventScope {
            while (true) {
                // Watching, not taking: the touch still does what it did.
                awaitPointerEvent(androidx.compose.ui.input.pointer.PointerEventPass.Initial)
                val now = android.os.SystemClock.uptimeMillis()
                lastInput.longValue = now
                val started = startedAt.longValue
                if (started != 0L) {
                    val turned = MarsTrip.afterTouch(now - started)
                    startedAt.longValue = now - turned
                }
            }
        }
    }
    return androidx.compose.runtime.remember(frame, touch) { MarsTripState(frame, touch) }
}
