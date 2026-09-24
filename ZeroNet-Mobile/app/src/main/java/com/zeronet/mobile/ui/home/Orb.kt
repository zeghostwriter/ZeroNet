package com.zeronet.mobile.ui.home

import android.graphics.Matrix
import android.os.Build
import android.view.HapticFeedbackConstants
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.FloatState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asComposePath
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.graphics.shapes.CornerRounding
import androidx.graphics.shapes.Morph
import androidx.graphics.shapes.RoundedPolygon
import androidx.graphics.shapes.circle
import androidx.graphics.shapes.star
import androidx.graphics.shapes.toPath
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroColors
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.theme.latinTracking
import kotlin.math.PI
import kotlin.math.cos

/** The orb's visual state (TUI `OrbState`). */
enum class OrbPhase { Idle, Busy, Connected, Failed }

/** Ring radii as fractions of the outer ring (TUI `RING_SCALES`). */
private val RING_SCALES = floatArrayOf(1.0f, 0.80f, 0.62f)

/**
 * A clock in milliseconds that advances every frame only while [running] and
 * the screen is at least RESUMED. It is read exclusively inside draw lambdas,
 * so ticking it invalidates drawing, never composition.
 */
@Composable
fun rememberAmbientClock(running: Boolean): FloatState {
    val time = remember { mutableFloatStateOf(0f) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(running, lifecycle) {
        if (!running) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            var last = -1L
            while (true) {
                withFrameNanos { now ->
                    if (last >= 0) time.floatValue += (now - last) / 1_000_000f
                    last = now
                }
            }
        }
    }
    return time
}

/** The orb's ring colours for one phase at one instant (TUI `RingPalette::for_state`). */
private fun ringColor(c: ZeroColors, phase: OrbPhase, ring: Int, breath: Float, pressed: Float): Color {
    // On light backgrounds the hairline border is too faint for the orb's rings; lift it toward muted.
    val rim = if (c.isDark) c.border else lerp(c.border, c.muted, 0.35f)
    val busyRim = if (c.isDark) c.accentDim else lerp(c.accentDim, c.accent, 0.45f)
    return when (phase) {
        OrbPhase.Idle -> when (ring) {
            0 -> lerp(rim, c.accent, pressed)
            1 -> lerp(rim, busyRim, pressed)
            else -> rim
        }
        OrbPhase.Busy -> when (ring) {
            0 -> busyRim
            else -> rim
        }
        OrbPhase.Connected -> when (ring) {
            0 -> lerp(lerp(c.ok, c.bg, 0.3f), c.okBright, breath)
            1 -> lerp(c.okDeep, c.ok, breath)
            else -> lerp(c.okDeep, c.bg, 0.3f)
        }
        OrbPhase.Failed -> when (ring) {
            0 -> c.err
            1 -> c.errDeep
            else -> rim
        }
    }
}

/**
 * The connect orb: a Compose translation of `zeronet-tui/src/connect_orb.rs`.
 *
 * Three concentric rings (1.0 / 0.80 / 0.62). Idle is dim; Busy sweeps a
 * bright 90° arc around the outer ring (with a shorter trailing arc on the
 * middle one) while the inner ring slowly morphs between a circle and a
 * 12-sided cookie; Connected turns green and breathes, with a one-shot ripple
 * and a soft glow; Failed shows a broken red ring. State changes cross-fade
 * the ring colours, as the TUI does.
 *
 * Every continuous value is read inside the draw lambda, so animation costs a
 * redraw per frame and no recomposition.
 */
@Composable
fun ConnectOrb(
    phase: OrbPhase,
    label: String,
    actionLabel: String,
    stateText: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val view = LocalView.current

    val ambient = !reduced && (phase == OrbPhase.Busy || phase == OrbPhase.Connected)
    val clock = rememberAmbientClock(ambient)

    // Cross-fade between the previous and current phase.
    var previous by remember { mutableStateOf(phase) }
    var current by remember { mutableStateOf(phase) }
    val mix = remember { Animatable(1f) }
    val busyAmount = remember { Animatable(if (phase == OrbPhase.Busy) 1f else 0f) }
    val ripple = remember { Animatable(1f) }
    val glow = remember { Animatable(if (phase == OrbPhase.Connected) 1f else 0f) }
    val press = remember { Animatable(0f) }
    val scale = remember { Animatable(1f) }

    LaunchedEffect(phase) {
        if (phase == current) return@LaunchedEffect
        previous = current
        current = phase
        mix.snapTo(0f)
        if (phase == OrbPhase.Connected) {
            val constant = if (Build.VERSION.SDK_INT >= 30) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.LONG_PRESS
            view.performHapticFeedback(constant)
        } else if (phase == OrbPhase.Failed && Build.VERSION.SDK_INT >= 30) {
            view.performHapticFeedback(HapticFeedbackConstants.REJECT)
        }
        if (reduced) {
            mix.animateTo(1f, tween(150))
            busyAmount.snapTo(if (phase == OrbPhase.Busy) 1f else 0f)
            glow.snapTo(if (phase == OrbPhase.Connected) 1f else 0f)
            return@LaunchedEffect
        }
        kotlinx.coroutines.coroutineScope {
            launch { mix.animateTo(1f, tween(460, easing = { t -> 1f - (1f - t) * (1f - t) * (1f - t) })) }
            launch { busyAmount.animateTo(if (phase == OrbPhase.Busy) 1f else 0f, ZeroMotion.standard()) }
            launch { glow.animateTo(if (phase == OrbPhase.Connected) 1f else 0f, tween(900)) }
            if (phase == OrbPhase.Connected) {
                launch {
                    ripple.snapTo(0f)
                    ripple.animateTo(1f, tween(1100, easing = LinearEasing))
                }
                launch {
                    scale.animateTo(1.04f, ZeroMotion.expressive())
                    scale.animateTo(1f, ZeroMotion.expressive())
                }
            }
        }
    }

    val interaction = remember { MutableInteractionSource() }
    LaunchedEffect(interaction, reduced) {
        interaction.interactions.collect { i ->
            when (i) {
                is PressInteraction.Press -> {
                    view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
                    launch { press.animateTo(1f, tween(120)) }
                    if (!reduced) launch { scale.animateTo(0.96f, ZeroMotion.snappy()) }
                }
                is PressInteraction.Release, is PressInteraction.Cancel -> {
                    launch { press.animateTo(0f, tween(260)) }
                    if (!reduced) launch { scale.animateTo(1f, ZeroMotion.expressive()) }
                }
            }
        }
    }

    // Shapes are normalised to radius 1 around the origin; one Morph, one Path, reused every frame.
    val morph = remember {
        Morph(
            RoundedPolygon.circle(numVertices = 12),
            RoundedPolygon.star(
                numVerticesPerRadius = 12,
                radius = 1f,
                innerRadius = 0.86f,
                rounding = CornerRounding(0.28f),
                innerRounding = CornerRounding(0.28f),
            ),
        )
    }

    Box(
        modifier
            .aspectRatio(1f)
            .graphicsLayer { scaleX = scale.value; scaleY = scale.value }
            .clip(CircleShape)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClickLabel = actionLabel,
                onClick = onClick,
            )
            .semantics {
                contentDescription = actionLabel
                stateDescription = stateText
            }
            .drawWithCache {
                val androidPath = android.graphics.Path()
                val composePath = androidPath.asComposePath()
                val matrix = Matrix()
                val outer = size.minDimension / 2f * 0.80f
                val center = Offset(size.width / 2f, size.height / 2f)
                val w0 = 3.dp.toPx()
                val w1 = 2.dp.toPx()
                val w2 = 1.75.dp.toPx()
                val arcWidth = 4.dp.toPx()
                val dash = PathEffect.dashPathEffect(floatArrayOf(outer * 2f * PI.toFloat() / 32f, outer * 2f * PI.toFloat() / 32f), 0f)
                // Stroke styles are allocated once per size, never per frame.
                val strokes = arrayOf(Stroke(w0), Stroke(w1), Stroke(w2))
                val brokenStroke = Stroke(w0, pathEffect = dash)
                val arcStroke = Stroke(arcWidth, cap = StrokeCap.Round)
                val trailStroke = Stroke(w1 * 1.2f, cap = StrokeCap.Round)
                val rippleStroke = Stroke(w0)
                val glowBrush = Brush.radialGradient(
                    0f to c.ok.copy(alpha = if (c.isDark) 0.30f else 0.20f),
                    0.55f to c.ok.copy(alpha = if (c.isDark) 0.10f else 0.06f),
                    1f to Color.Transparent,
                    center = center,
                    radius = size.minDimension / 2f,
                )
                val busyGlow = Brush.radialGradient(
                    0f to c.accent.copy(alpha = if (c.isDark) 0.14f else 0.10f),
                    1f to Color.Transparent,
                    center = center,
                    radius = size.minDimension / 2f,
                )
                val core = Brush.radialGradient(
                    0f to lerp(c.surfaceHi, c.surface, 0.2f),
                    1f to c.surface,
                    center = center - Offset(0f, outer * 0.25f),
                    radius = outer,
                )
                val arcBrush = Brush.sweepGradient(
                    0f to Color.Transparent,
                    0.16f to c.accentHot.copy(alpha = 0.5f),
                    0.25f to c.accentBright,
                    0.2501f to Color.Transparent,
                    1f to Color.Transparent,
                    center = center,
                )

                onDrawBehind {
                    val t = clock.floatValue
                    val breath = if (reduced) 0.5f else (0.5f - 0.5f * cos(2f * PI.toFloat() * t / ZeroMotion.BREATH_PERIOD_MS))
                    val p = press.value
                    val m = mix.value
                    val busy = busyAmount.value

                    // Soft radial glow behind the orb.
                    if (glow.value > 0.001f) drawRect(glowBrush, alpha = glow.value * (0.75f + 0.25f * breath))
                    if (busy > 0.001f) drawRect(busyGlow, alpha = busy)

                    // Inner core: the morphing shape, filled and outlined.
                    val morphT = if (reduced) 0f else busy * (0.5f - 0.5f * cos(2f * PI.toFloat() * t / ZeroMotion.MORPH_PERIOD_MS))
                    val coreR = outer * RING_SCALES[2]
                    androidPath.rewind()
                    morph.toPath(morphT, androidPath)
                    matrix.reset()
                    matrix.setScale(coreR, coreR)
                    matrix.postRotate(t / 90f * busy)
                    matrix.postTranslate(center.x, center.y)
                    androidPath.transform(matrix)
                    drawPath(composePath, core)

                    // Rings, colours cross-faded from the previous phase.
                    for (i in 0..2) {
                        val color = lerp(
                            ringColor(c, previous, i, breath, p),
                            ringColor(c, current, i, breath, p),
                            m,
                        )
                        if (i == 2) {
                            drawPath(composePath, color, style = strokes[2])
                        } else {
                            val broken = i == 0 && current == OrbPhase.Failed
                            drawCircle(
                                color = color,
                                radius = outer * RING_SCALES[i],
                                center = center,
                                style = if (broken) brokenStroke else strokes[i],
                            )
                        }
                    }

                    // The sweeping arc and its shorter trailing arc.
                    if (busy > 0.001f) {
                        val spin = if (reduced) 0f else t / ZeroMotion.SWEEP_PERIOD_MS * 360f
                        rotate(spin, center) {
                            drawCircle(arcBrush, radius = outer, center = center, alpha = busy, style = arcStroke)
                        }
                        rotate(spin - 28.6f, center) {
                            val r1 = outer * RING_SCALES[1]
                            drawArc(
                                color = c.accent.copy(alpha = 0.55f * busy),
                                startAngle = -90f - 54f,
                                sweepAngle = 54f,
                                useCenter = false,
                                topLeft = Offset(center.x - r1, center.y - r1),
                                size = Size(r1 * 2, r1 * 2),
                                style = trailStroke,
                            )
                        }
                    }

                    // One-shot ripple on arrival at Connected.
                    val r = ripple.value
                    if (r < 1f && current == OrbPhase.Connected) {
                        drawCircle(
                            color = c.ok.copy(alpha = (1f - r) * 0.6f),
                            radius = outer * (1f + 0.22f * r),
                            center = center,
                            style = rippleStroke,
                        )
                    }
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        OrbLabel(label, phase)
    }
}

@Composable
private fun OrbLabel(label: String, phase: OrbPhase) {
    val c = ZeroTheme.colors
    val color = when (phase) {
        OrbPhase.Idle -> c.text
        OrbPhase.Busy -> c.accent
        OrbPhase.Connected -> c.ok
        OrbPhase.Failed -> c.err
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(horizontal = 40.dp)) {
        Text(
            text = label,
            color = color,
            style = MaterialTheme.typography.titleMedium.copy(
                fontWeight = FontWeight.Bold,
                fontSize = 17.sp,
                letterSpacing = latinTracking(0.14),
            ),
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
