package com.zeronet.mobile.ui.effects

import android.view.HapticFeedbackConstants
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.FloatState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import kotlinx.coroutines.delay

/** The controller's buttons, in the order the animation presses them. */
enum class Pad { LeftStick, DPadRight, X, Y, B, A, RightStick, LeftBumper, RightBumper, LeftTrigger, RightTrigger }

/**
 * The clock of the gaming switch-on scene. Every function here takes the time
 * since the scene began, in milliseconds, and answers one question about that
 * moment; nothing here draws or keeps state, so it can be tested on its own.
 *
 * The scene in order: the controller flies in ([DROP_IN_MS]), its buttons are
 * pressed one after another and each press adds to the charge, both triggers
 * are pulled and held, and at [IGNITE_MS] the controller ignites: a shockwave
 * goes out and the words appear. It fades from [FADE_FROM_MS] to [TOTAL_MS].
 */
object GamepadTimeline {
    /** Milliseconds from the start until each button is pressed. The two triggers go down together. */
    val presses: List<Pair<Pad, Int>> = listOf(
        Pad.LeftStick to 600, Pad.DPadRight to 760, Pad.X to 900, Pad.Y to 1020, Pad.B to 1140, Pad.A to 1260,
        Pad.RightStick to 1400, Pad.LeftBumper to 1560, Pad.RightBumper to 1680,
        Pad.LeftTrigger to 1880, Pad.RightTrigger to 1880,
    )
    const val PRESS_MS = 190
    const val SPARK_MS = 420
    const val DROP_IN_MS = 520
    const val IGNITE_MS = 2100
    const val FADE_FROM_MS = 3750
    const val TOTAL_MS = 4200

    /** The moment shown, unmoving, when motion is reduced: lit up, words out, the shockwave long gone. */
    const val STILL_MS = 3000f

    private const val DOWN_MS = 40f
    private const val UP_MS = 60f
    private const val CHARGE_MS = 140f

    private fun at(pad: Pad): Int = presses.first { it.first == pad }.second

    /** How long [pad] stays pressed. A trigger is held until just after the ignition, the rest for [PRESS_MS]. */
    fun length(pad: Pad): Int =
        if (pad == Pad.LeftTrigger || pad == Pad.RightTrigger) IGNITE_MS + 90 - at(pad) else PRESS_MS

    /** How far down [pad] is at [ms]: 0 up, 1 fully pressed. It goes down fast, is held, and comes back up. */
    fun depth(pad: Pad, ms: Float): Float {
        val t = ms - at(pad)
        val end = length(pad).toFloat()
        return when {
            t < 0f || t > end -> 0f
            t < DOWN_MS -> t / DOWN_MS
            t < end - UP_MS -> 1f
            else -> (end - t) / UP_MS
        }
    }

    /**
     * How far through the [over] milliseconds after its press [pad] is, `0..1`,
     * or -1 when [ms] is outside that window. Used for things a press starts
     * and that outlive it, like its sparks.
     */
    fun phase(pad: Pad, ms: Float, over: Float): Float {
        val t = ms - at(pad)
        return if (t < 0f || t > over) -1f else t / over
    }

    /** The buttons pressed on the frame at [now] that were not pressed on the frame at [before]. */
    fun newPresses(before: Float, now: Float): List<Pad> =
        presses.filter { (_, at) -> before < at && now >= at }.map { it.first }

    /** How lit the charge ring's segment number [index] is, `0..1`: it comes on with the press of that number. */
    fun lit(index: Int, ms: Float): Float = ((ms - presses[index].second) / CHARGE_MS).coerceIn(0f, 1f)

    /** How charged the controller is, `0..1`: each press adds an equal share, and it never goes back down. */
    fun charge(ms: Float): Float = presses.indices.sumOf { lit(it, ms).toDouble() }.toFloat() / presses.size

    /** The jolt of the ignition: 1 at [IGNITE_MS], dying away over half a second, 0 before it. */
    fun kick(ms: Float): Float {
        val t = ms - IGNITE_MS
        if (t < 0f) return 0f
        val left = (1f - t / 500f).coerceIn(0f, 1f)
        return left * left
    }

    /** The whole scene's opacity: in at the start, out at the end. */
    fun opacity(ms: Float): Float = when {
        ms < 160f -> (ms / 160f).coerceIn(0f, 1f)
        ms > FADE_FROM_MS -> (1f - (ms - FADE_FROM_MS) / (TOTAL_MS - FADE_FROM_MS)).coerceIn(0f, 1f)
        else -> 1f
    }

    /** How far the controller has flown into place, with a small overshoot: `0..~1.08`, 1 from [DROP_IN_MS] on. */
    fun drop(ms: Float): Float {
        val t = (ms / DROP_IN_MS).coerceIn(0f, 1f)
        return 1f + 2.4f * (t - 1f) * (t - 1f) * (t - 1f) + 1.4f * (t - 1f) * (t - 1f)
    }

    /**
     * How hard the streaks around the controller rush outwards, `0..1`: fast
     * while it flies in and again right after the ignition, calm in between.
     */
    fun rush(ms: Float): Float {
        val arriving = 1f - ms / 800f
        val ignited = if (ms < IGNITE_MS) 0f else 1f - (ms - IGNITE_MS) / 700f
        return maxOf(arriving, ignited, 0f)
    }
}

/**
 * Watches the connection profile and plays the gaming scene each time it
 * changes to Gaming. It belongs at the root of the app, above every screen:
 * the profile is picked in Settings, and that is where the person is looking
 * when it changes.
 *
 * It does not play for a profile that was already Gaming when the app opened,
 * and switching away from Gaming in the middle of the scene ends it.
 */
@Composable
fun GamingIntro(profile: ConnectionProfile, modifier: Modifier = Modifier) {
    var plays by remember { mutableIntStateOf(0) }
    var last by remember { mutableStateOf(profile) }
    LaunchedEffect(profile) {
        if (profile == ConnectionProfile.Gaming && last != ConnectionProfile.Gaming) plays += 1
        last = profile
    }
    if (profile == ConnectionProfile.Gaming) GamepadBurst(plays, modifier)
}

/**
 * Plays the gaming scene once each time [playId] changes (and [playId] is not
 * 0): a night backdrop over the whole screen, the controller in the middle
 * with a ring around it that charges as the buttons are pressed, then the
 * ignition and the words.
 *
 * While it plays it takes every touch, so nothing underneath can be pressed
 * by accident; a tap skips to the fade. With reduced motion it is one still
 * picture, held long enough to read.
 *
 * The clock is read only while drawing, so a frame costs a redraw and never a
 * recomposition.
 */
@Composable
fun GamepadBurst(playId: Int, modifier: Modifier = Modifier) {
    if (playId == 0) return
    val reduced = LocalReducedMotion.current
    val view = LocalView.current
    val clock = remember(playId) { mutableFloatStateOf(0f) }
    // Milliseconds a tap has added to the clock to jump ahead to the fade.
    val skipped = remember(playId) { mutableFloatStateOf(0f) }
    var done by remember(playId) { mutableStateOf(false) }
    LaunchedEffect(playId, reduced) {
        if (reduced) {
            clock.floatValue = GamepadTimeline.STILL_MS
            delay(2200)
            done = true
            return@LaunchedEffect
        }
        val begin = withFrameNanos { it }
        var last = 0f
        while (last < GamepadTimeline.TOTAL_MS) {
            val frame = withFrameNanos { it }
            val now = (frame - begin) / 1_000_000f + skipped.floatValue
            // A skip jumps over presses; those are not felt.
            if (now - last < 100f) {
                if (last < GamepadTimeline.IGNITE_MS && now >= GamepadTimeline.IGNITE_MS) {
                    view.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
                } else if (GamepadTimeline.newPresses(last, now).isNotEmpty()) {
                    view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
                }
            }
            last = now
            clock.floatValue = now
        }
        done = true
    }
    if (done) return
    BoxWithConstraints(
        modifier
            .fillMaxSize()
            .pointerInput(playId, reduced) {
                detectTapGestures {
                    if (reduced) {
                        done = true
                    } else if (clock.floatValue < GamepadTimeline.FADE_FROM_MS) {
                        skipped.floatValue += GamepadTimeline.FADE_FROM_MS - clock.floatValue
                    }
                }
            }
            .graphicsLayer { alpha = GamepadTimeline.opacity(clock.floatValue) },
    ) {
        val padWidth = minOf(maxWidth * 0.70f, maxHeight * 0.36f, 320.dp)
        val padHeight = padWidth * (GamepadArt.H / GamepadArt.W)
        val ring = padWidth * 0.62f
        val art = remember { GamepadArt() }
        Canvas(Modifier.fillMaxSize()) { drawStage(clock.floatValue, ring.toPx(), still = reduced) }
        // Equal weights above and below keep the controller on the screen's
        // centre, which is where the ring and the shockwave are drawn from.
        Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.weight(1f))
            Canvas(
                Modifier
                    .size(padWidth, padHeight)
                    .graphicsLayer {
                        val ms = clock.floatValue
                        val d = GamepadTimeline.drop(ms)
                        val kick = GamepadTimeline.kick(ms)
                        val float = if (reduced) 0f else 1f
                        // It arrives small, tipped back and edge-on, and swings open as it lands.
                        val s = 0.25f + 0.75f * d + 0.10f * kick
                        scaleX = s
                        scaleY = s
                        rotationX = 55f * (1f - d) + 5f * sin(ms / 700f) * float
                        rotationY = -90f * (1f - d) + 7f * sin(ms / 900f) * float
                        rotationZ = 4f * sin(ms * 0.09f) * kick
                        translationY = (-40f * (1f - d) + 4f * sin(ms / 520f) * float) * density
                        cameraDistance = 14f * density
                    },
            ) { drawGamepad(art, clock.floatValue) }
            Box(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(top = ring - padHeight / 2 + 18.dp, start = 28.dp, end = 28.dp),
                contentAlignment = Alignment.TopCenter,
            ) { Words(clock) }
        }
        Canvas(Modifier.fillMaxSize()) { drawIgnition(clock.floatValue, ring.toPx()) }
    }
}

/**
 * The words under the controller. The title lands at the ignition, oversized
 * and split into its cyan and magenta ghosts, and settles; the note about what
 * gaming mode trades away follows it up.
 */
@Composable
private fun Words(clock: FloatState) {
    val title = stringResource(R.string.gaming_on_title)
    val style = MaterialTheme.typography.headlineMedium.copy(fontWeight = FontWeight.ExtraBold)
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier.graphicsLayer {
                val t = clock.floatValue - GamepadTimeline.IGNITE_MS
                val land = (t / 260f).coerceIn(0f, 1f)
                val s = 1.7f - 0.7f * overshoot(land)
                scaleX = s
                scaleY = s
                alpha = (t / 80f).coerceIn(0f, 1f)
            },
            contentAlignment = Alignment.Center,
        ) {
            for ((color, side) in listOf(Neon.Magenta to -1f, Neon.Cyan to 1f)) {
                Text(
                    title,
                    style = style,
                    color = color,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        // The ghosts are decoration: a screen reader should meet the title once.
                        .clearAndSetSemantics {}
                        .graphicsLayer {
                            val t = clock.floatValue - GamepadTimeline.IGNITE_MS
                            val settle = (t / 600f).coerceIn(0f, 1f)
                            translationX = side * (1.5f + 8f * (1f - settle)) * density
                            alpha = 0.85f
                        },
                )
            }
            Text(title, style = style, color = Color.White, textAlign = TextAlign.Center)
        }
        Text(
            stringResource(R.string.gaming_on_note),
            style = MaterialTheme.typography.bodyMedium,
            color = Color.White.copy(alpha = 0.86f),
            textAlign = TextAlign.Center,
            modifier = Modifier
                .padding(top = 8.dp)
                .graphicsLayer {
                    val shown = ((clock.floatValue - GamepadTimeline.IGNITE_MS - 180f) / 220f).coerceIn(0f, 1f)
                    alpha = shown
                    translationY = (1f - shown) * 10f * density
                },
        )
    }
}

// ---------------------------------------------------------------- drawing

private const val STREAKS = 48

/**
 * Behind the controller: the night backdrop with a glow in the middle, the
 * streaks rushing outwards, and the charge ring. [ring] is the ring's radius
 * in pixels. [still] leaves the streaks out, for reduced motion.
 */
private fun DrawScope.drawStage(ms: Float, ring: Float, still: Boolean) {
    val charge = GamepadTimeline.charge(ms)
    val kick = GamepadTimeline.kick(ms)
    drawRect(Neon.Night.copy(alpha = 0.97f))
    drawRect(
        Brush.radialGradient(
            listOf(lerp(Neon.Cyan, Neon.Magenta, charge).copy(alpha = 0.10f + 0.16f * charge + 0.14f * kick), Color.Transparent),
            center = center,
            radius = ring * 2.3f,
        ),
    )
    if (!still) drawStreaks(ms, ring)
    drawChargeRing(ms, ring * (1f + 0.07f * kick), shown = GamepadTimeline.drop(ms).coerceIn(0f, 1f))
}

/**
 * Thin lines flying out from the middle, as if the scene were moving forwards.
 * Each one has its own direction, speed and starting point, picked by [noise]
 * so they are the same on every run, and loops for as long as the scene lasts.
 */
private fun DrawScope.drawStreaks(ms: Float, ring: Float) {
    val rush = GamepadTimeline.rush(ms)
    val reach = size.maxDimension * 0.75f
    val width = 1.2.dp.toPx()
    for (i in 0 until STREAKS) {
        val angle = noise(i, 1) * 2f * PI.toFloat()
        val period = 900f + 1400f * noise(i, 2)
        val along = (ms / period + noise(i, 3)) % 1f
        val dir = Offset(cos(angle), sin(angle))
        val from = ring * 0.55f + along * along * reach
        val length = (6.dp.toPx() + 34.dp.toPx() * along) * (0.6f + rush)
        val alpha = sin(along * PI.toFloat()) * (0.10f + 0.50f * rush)
        drawLine(
            (if (i % 3 == 0) Neon.Magenta else Neon.Cyan).copy(alpha = alpha),
            center + dir * from,
            center + dir * (from + length),
            strokeWidth = width,
            cap = StrokeCap.Round,
        )
    }
}

/**
 * The ring around the controller: one segment for each press, dark until that
 * press happens and lit from then on, cyan at the first running to magenta at
 * the last. It turns slowly, and a ring of fine ticks turns the other way
 * outside it.
 */
private fun DrawScope.drawChargeRing(ms: Float, radius: Float, shown: Float) {
    val count = GamepadTimeline.presses.size
    val sweep = 360f / count
    val gap = 5f
    val turn = ms * 0.012f - 90f
    val box = Size(radius * 2f, radius * 2f)
    val corner = center - Offset(radius, radius)
    for (i in 0 until count) {
        val lit = GamepadTimeline.lit(i, ms)
        val color = lerp(Neon.Cyan, Neon.Magenta, i / (count - 1f))
        val start = turn + i * sweep + gap / 2f
        drawArc(Color.White.copy(alpha = 0.10f * shown), start, sweep - gap, false, corner, box, style = Stroke(2.dp.toPx()))
        if (lit > 0f) {
            drawArc(color.copy(alpha = 0.20f * lit * shown), start, sweep - gap, false, corner, box, style = Stroke(10.dp.toPx()))
            drawArc(color.copy(alpha = lit * shown), start, sweep - gap, false, corner, box, style = Stroke(3.dp.toPx()))
        }
    }
    val outer = radius * 1.10f
    for (i in 0 until 72) {
        val angle = (i * 5f - ms * 0.008f) * PI.toFloat() / 180f
        val dir = Offset(cos(angle), sin(angle))
        val long = i % 6 == 0
        drawLine(
            Color.White.copy(alpha = (if (long) 0.30f else 0.12f) * shown),
            center + dir * outer,
            center + dir * (outer + (if (long) 7.dp.toPx() else 3.dp.toPx())),
            strokeWidth = 1.dp.toPx(),
        )
    }
}

/** In front of everything: the two shockwaves that leave the ring at the ignition, and the flash. */
private fun DrawScope.drawIgnition(ms: Float, ring: Float) {
    val t = ms - GamepadTimeline.IGNITE_MS
    if (t < 0f) return
    for ((wait, color) in listOf(0f to Neon.Magenta, 90f to Neon.Cyan)) {
        val q = (t - wait) / 700f
        if (q <= 0f || q >= 1f) continue
        val out = 1f - (1f - q) * (1f - q) * (1f - q)
        drawCircle(
            color.copy(alpha = (1f - q) * 0.9f),
            radius = ring + out * size.maxDimension,
            center = center,
            style = Stroke((1f - q) * 14.dp.toPx() + 1.dp.toPx()),
        )
    }
    if (t < 200f) drawRect(Color.White.copy(alpha = 0.30f * (1f - t / 200f)))
}

/** A fixed pseudo-random number in `0..1` for streak [index]; [salt] picks which of its properties. */
private fun noise(index: Int, salt: Int): Float {
    var h = index * 374761393 + salt * 668265263
    h = (h xor (h ushr 13)) * 1274126177
    return ((h xor (h ushr 16)) and 0xffff) / 65535f
}

/** Ease-out that goes a little past 1 before settling on it. */
private fun overshoot(t: Float): Float {
    val u = t - 1f
    return 1f + 2.70158f * u * u * u + 1.70158f * u * u
}
