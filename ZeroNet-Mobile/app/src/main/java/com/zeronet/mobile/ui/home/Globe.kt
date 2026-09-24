package com.zeronet.mobile.ui.home

import android.os.Build
import android.view.HapticFeedbackConstants
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.theme.latinTracking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.PI
import kotlin.math.acos
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/** Arc resolution: points along the route. */
private const val ARC_POINTS = 72

/** Points on each radar ring drawn around the user's location while searching. */
private const val RADAR_POINTS = 48

/**
 * The connect button: a wireframe Earth, lines only — a 15° graticule and the
 * real coastlines — with a great-circle route from the user's location to the
 * server's country.
 *
 * - Idle: the globe sways gently around the user's location. With a server or
 *   country chosen, the route is previewed, dimmed.
 * - Searching: radar rings pulse out from the user's location.
 * - Connecting to a known server: the globe turns to face the route and a
 *   comet runs along it.
 * - Connected: the route draws in, then a light pulse travels along it and
 *   both ends breathe.
 * - Failed: the route breaks into dashes.
 *
 * Gaming mode adds a one-shot activation (shockwave, warp lines, flash,
 * scanline, chromatic glitch, a "GAME MODE" title slam) and persistent HUD
 * brackets with a live ping readout.
 *
 * Everything moving is read in the draw phase: animation costs redraws, never
 * recomposition, and ambient motion is capped at ~30 fps by the clock.
 */
@Composable
fun ConnectGlobe(
    phase: OrbPhase,
    label: String,
    actionLabel: String,
    stateText: String,
    destination: String?,
    gaming: Boolean,
    gamingTitle: String,
    hudText: String?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val view = LocalView.current
    val context = LocalContext.current

    val data by produceState<GlobeData?>(null) {
        value = withContext(Dispatchers.IO) { runCatching { GlobeData.load(context) }.getOrNull() }
    }
    val home = remember(data) { data?.let { userLocation(context, it) } ?: LatLon(35.69f, 51.39f) }
    val target = remember(data, destination) { destination?.let { data?.country(it) } }
    val route = remember(home, target) { target?.let { buildRoute(home, it) } }

    val clock = rememberAmbientClock(!reduced)

    val tint by animateColorAsState(
        when (phase) {
            OrbPhase.Idle, OrbPhase.Busy -> c.accent
            OrbPhase.Connected -> c.ok
            OrbPhase.Failed -> c.err
        },
        tween(ZeroMotion.ms(if (reduced) 150 else 600)),
        label = "globeTint",
    )
    val arcColor by animateColorAsState(
        when {
            phase == OrbPhase.Failed -> c.err
            gaming -> c.accentHot
            phase == OrbPhase.Connected -> c.okBright
            else -> c.accentBright
        },
        tween(ZeroMotion.ms(if (reduced) 150 else 500)),
        label = "globeArc",
    )

    // Camera: 0 = sway around the user, 1 = face the route.
    val focus = remember { Animatable(0f) }
    val wantsFocus = route != null && phase != OrbPhase.Idle
    LaunchedEffect(wantsFocus, reduced) {
        val to = if (wantsFocus) 1f else 0f
        if (reduced) focus.snapTo(to) else focus.animateTo(to, tween(ZeroMotion.ms(1400), easing = EaseInOutCubic))
    }
    // How much of the route is drawn: previewed at idle, drawn in on connect.
    val reveal = remember { Animatable(0f) }
    LaunchedEffect(route, phase, reduced) {
        val to = when {
            route == null -> 0f
            phase == OrbPhase.Connected || phase == OrbPhase.Failed || phase == OrbPhase.Idle -> 1f
            else -> 0f
        }
        if (reduced || to == 0f) reveal.snapTo(to) else reveal.animateTo(to, tween(ZeroMotion.ms(1100), easing = EaseOutCubic))
    }

    // Orbit rings: they appear and spin while connecting, then slow down and
    // hold still once connected. Speed is integrated in the draw phase, so a
    // ring that is slowing keeps its angle rather than jumping.
    val orbitPresence = remember { Animatable(0f) }
    val orbitSpeed = remember { Animatable(0f) }
    LaunchedEffect(phase, reduced) {
        val present = when (phase) {
            OrbPhase.Busy, OrbPhase.Connected -> 1f
            OrbPhase.Failed -> 0.35f
            OrbPhase.Idle -> 0f
        }
        val speed = if (phase == OrbPhase.Busy && !reduced) 1f else 0f
        if (reduced) {
            orbitPresence.snapTo(present); orbitSpeed.snapTo(0f)
            return@LaunchedEffect
        }
        coroutineScope {
            launch { orbitPresence.animateTo(present, tween(ZeroMotion.ms(if (present > 0f) 700 else 450))) }
            launch { orbitSpeed.animateTo(speed, tween(ZeroMotion.ms(if (speed > 0f) 500 else 1800), easing = EaseOutCubic)) }
        }
    }

    // One-shot effects.
    val ripple = remember { Animatable(1f) }
    val press = remember { Animatable(0f) }
    val scale = remember { Animatable(1f) }
    var lastPhase by remember { mutableStateOf(phase) }
    LaunchedEffect(phase) {
        if (phase == lastPhase) return@LaunchedEffect
        lastPhase = phase
        if (phase == OrbPhase.Connected) {
            val constant = if (Build.VERSION.SDK_INT >= 30) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.LONG_PRESS
            view.performHapticFeedback(constant)
            if (!reduced) coroutineScope {
                launch { ripple.snapTo(0f); ripple.animateTo(1f, tween(ZeroMotion.ms(1200), easing = LinearEasing)) }
                launch { scale.animateTo(1.04f, ZeroMotion.expressive()); scale.animateTo(1f, ZeroMotion.expressive()) }
            }
        } else if (phase == OrbPhase.Failed && Build.VERSION.SDK_INT >= 30) {
            view.performHapticFeedback(HapticFeedbackConstants.REJECT)
        }
    }

    // Gaming: activation burst, title slam, HUD brackets.
    val boost = remember { Animatable(1f) }
    val hud = remember { Animatable(if (gaming) 1f else 0f) }
    var gamingSeen by remember { mutableStateOf(gaming) }
    LaunchedEffect(gaming, reduced) {
        if (gaming == gamingSeen) {
            hud.snapTo(if (gaming) 1f else 0f)
            return@LaunchedEffect
        }
        gamingSeen = gaming
        if (reduced) {
            hud.animateTo(if (gaming) 1f else 0f, tween(ZeroMotion.ms(150)))
            return@LaunchedEffect
        }
        if (gaming) {
            coroutineScope {
                // A short rumble: three quick ticks, then a heavy one.
                launch {
                    repeat(3) {
                        view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                        delay(ZeroMotion.ms(55).toLong())
                    }
                    view.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
                }
                launch { boost.snapTo(0f); boost.animateTo(1f, tween(ZeroMotion.ms(1500), easing = LinearEasing)) }
                launch { hud.snapTo(0f); delay(ZeroMotion.ms(250).toLong()); hud.animateTo(1f, ZeroMotion.expressive()) }
            }
        } else {
            hud.animateTo(0f, tween(ZeroMotion.ms(260)))
        }
    }

    val interaction = remember { MutableInteractionSource() }
    LaunchedEffect(interaction, reduced) {
        interaction.interactions.collect { i ->
            when (i) {
                is PressInteraction.Press -> {
                    view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
                    launch { press.animateTo(1f, tween(ZeroMotion.ms(120))) }
                    if (!reduced) launch { scale.animateTo(0.95f, ZeroMotion.snappy()) }
                }
                is PressInteraction.Release, is PressInteraction.Cancel -> {
                    launch { press.animateTo(0f, tween(ZeroMotion.ms(260))) }
                    if (!reduced) launch { scale.animateTo(1f, ZeroMotion.expressive()) }
                }
            }
        }
    }

    val phaseNow by rememberUpdatedState(phase)
    val gamingNow by rememberUpdatedState(gaming)

    Box(
        modifier
            .aspectRatio(1f)
            // Drawn above its siblings: the gaming burst spills over the screen.
            .zIndex(1f)
            .graphicsLayer { scaleX = scale.value; scaleY = scale.value }
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
                val camera = GlobeCamera()
                val frontGrid = Path(); val backGrid = Path()
                val frontCoast = Path(); val backCoast = Path()
                val arcPath = Path(); val cometPath = Path(); val ringPath = Path()
                val radius = size.minDimension / 2f * 0.84f
                val center = Offset(size.width / 2f, size.height / 2f)
                val thin = Stroke(0.8.dp.toPx())
                val coastStroke = Stroke(1.4.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
                val coastGlow = Stroke(4.5.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
                val rim = Stroke(1.5.dp.toPx())
                val arcCore = Stroke(2.6.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
                val arcGlow = Stroke(9.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
                val broken = Stroke(
                    2.6.dp.toPx(),
                    cap = StrokeCap.Round,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 7.dp.toPx())),
                )
                val preview = Stroke(
                    1.8.dp.toPx(),
                    cap = StrokeCap.Round,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 5.dp.toPx())),
                )
                val dot = 3.5.dp.toPx()
                val orbitFront = Array(ORBITS.size) { Path() }
                val orbitBack = Array(ORBITS.size) { Path() }
                val orbitSolid = Stroke(1.6.dp.toPx(), cap = StrokeCap.Round)
                val orbitGlowStroke = Stroke(6.dp.toPx(), cap = StrokeCap.Round)
                val orbitDotted = Stroke(
                    1.6.dp.toPx(),
                    cap = StrokeCap.Round,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(0.1f, 6.dp.toPx())),
                )
                val arrow = Path()
                var spin = 0f
                var lastClock = -1f
                val bracket = Stroke(2.2.dp.toPx(), cap = StrokeCap.Square)
                val speedLine = Stroke(2.dp.toPx(), cap = StrokeCap.Round)
                val body = Brush.radialGradient(
                    0f to lerp(c.bg, c.accent, if (c.isDark) 0.10f else 0.06f),
                    0.75f to lerp(c.bg, c.surface, 0.5f),
                    1f to c.bg,
                    center = center - Offset(radius * 0.3f, radius * 0.35f),
                    radius = radius * 1.4f,
                )

                onDrawBehind {
                    val t = clock.floatValue
                    val p = phaseNow
                    val f = focus.value

                    // ---- camera
                    val swayLon = home.lon + if (reduced) 0f else 32f * sin(t / 11_000f * 2f * PI.toFloat())
                    val swayLat = 22f + if (reduced) 0f else 4f * sin(t / 7_000f * 2f * PI.toFloat())
                    val focusLon = (route?.center?.lon ?: home.lon) + if (reduced) 0f else 6f * sin(t / 6_000f * 2f * PI.toFloat())
                    val focusLat = (route?.center?.lat ?: home.lat).coerceIn(-35f, 55f)
                    camera.lookAt(swayLat + (focusLat - swayLat) * f, lerpLongitude(swayLon, focusLon, f))

                    // ---- atmosphere and body
                    val glowAlpha = (if (c.isDark) 0.30f else 0.18f) * (0.8f + 0.2f * press.value) *
                        (if (p == OrbPhase.Connected) 1.25f else 1f)
                    drawCircle(
                        Brush.radialGradient(
                            0.70f to tint.copy(alpha = glowAlpha),
                            0.86f to tint.copy(alpha = glowAlpha * 0.35f),
                            1f to Color.Transparent,
                            center = center,
                            radius = radius * 1.28f,
                        ),
                        radius = radius * 1.28f,
                        center = center,
                    )
                    // ---- orbits, back halves (the body then hides what is behind it)
                    if (lastClock >= 0f) spin += (t - lastClock).coerceIn(0f, 100f) * orbitSpeed.value
                    lastClock = t
                    val presence = orbitPresence.value
                    if (presence > 0.001f) {
                        orbitPaths(center, radius, spin, orbitFront, orbitBack)
                        for (k in ORBITS.indices) {
                            drawPath(orbitBack[k], tint.copy(alpha = 0.35f * presence), style = if (ORBITS[k].dotted) orbitDotted else orbitSolid)
                        }
                    }
                    drawCircle(body, radius = radius, center = center)

                    // ---- wireframe
                    val d = data
                    if (d != null) {
                        project(d.graticule, camera, center, radius, frontGrid, backGrid)
                        project(d.coast, camera, center, radius, frontCoast, backCoast)
                        drawPath(backGrid, tint.copy(alpha = 0.07f), style = thin)
                        drawPath(backCoast, tint.copy(alpha = 0.12f), style = thin)
                        drawPath(frontGrid, tint.copy(alpha = if (c.isDark) 0.30f else 0.38f), style = thin)
                        // Chromatic split while the gaming burst runs.
                        val b = boost.value
                        if (b < 0.5f) {
                            val jitter = glitchOffset(b) * 5.dp.toPx() * (1f - b * 2f)
                            translate(-jitter, 0f) { drawPath(frontCoast, Color(0xFFFF2BD6).copy(alpha = 0.55f), style = coastStroke) }
                            translate(jitter, jitter * 0.3f) { drawPath(frontCoast, Color(0xFF22E3FF).copy(alpha = 0.55f), style = coastStroke) }
                        }
                        drawPath(frontCoast, tint.copy(alpha = 0.16f), style = coastGlow)
                        drawPath(frontCoast, lerp(tint, c.text, 0.25f), style = coastStroke)
                    }
                    drawCircle(tint.copy(alpha = 0.75f), radius = radius, center = center, style = rim)

                    // ---- route
                    val r = route
                    if (r != null) {
                        val shown = reveal.value
                        when {
                            p == OrbPhase.Busy -> {
                                // A comet running from the user toward the server.
                                val head = (t % 1400f) / 1400f
                                arcSegment(r, camera, center, radius, (head - 0.35f).coerceAtLeast(0f), head, cometPath)
                                drawPath(cometPath, arcColor.copy(alpha = 0.35f), style = arcGlow)
                                drawPath(cometPath, arcColor, style = arcCore)
                                drawArrowHead(r, camera, center, radius, head, lerp(arcColor, Color.White, 0.5f), dot * 2.2f, arrow)
                            }
                            p == OrbPhase.Failed -> {
                                arcSegment(r, camera, center, radius, 0f, shown, arcPath)
                                drawPath(arcPath, arcColor, style = broken)
                            }
                            p == OrbPhase.Idle -> {
                                arcSegment(r, camera, center, radius, 0f, shown, arcPath)
                                drawPath(arcPath, arcColor.copy(alpha = 0.55f), style = preview)
                            }
                            else -> {
                                arcSegment(r, camera, center, radius, 0f, shown, arcPath)
                                drawPath(arcPath, arcColor.copy(alpha = 0.28f), style = arcGlow)
                                drawPath(arcPath, arcColor, style = arcCore)
                                if (shown >= 1f && !reduced) {
                                    val head = (t % 1700f) / 1700f
                                    arcSegment(r, camera, center, radius, (head - 0.12f).coerceAtLeast(0f), head, cometPath)
                                    drawPath(cometPath, lerp(arcColor, Color.White, 0.6f), style = arcCore)
                                    drawArrowHead(r, camera, center, radius, head, Color.White, dot * 2.2f, arrow)
                                }
                            }
                        }
                        drawEndpoint(r.to, camera, center, radius, arcColor, dot, if (reduced) 0f else (t + 700f) % 1600f / 1600f)
                    }

                    // ---- the user's location, with radar while searching
                    if (p == OrbPhase.Busy && r == null && !reduced) {
                        for (k in 0..1) {
                            val frac = ((t / 1800f) + k * 0.5f) % 1f
                            radarRing(home, frac * 32f, camera, center, radius, ringPath)
                            drawPath(ringPath, tint.copy(alpha = (1f - frac) * 0.8f), style = coastStroke)
                        }
                    }
                    drawEndpoint(home, camera, center, radius, lerp(tint, c.text, 0.4f), dot, if (reduced) 0f else t % 1600f / 1600f)

                    // ---- orbits, front halves, with sparkles riding them
                    if (presence > 0.001f) {
                        val sparkleColor = lerp(tint, Color.White, 0.65f)
                        for (k in ORBITS.indices) {
                            val o = ORBITS[k]
                            if (!o.dotted) drawPath(orbitFront[k], tint.copy(alpha = 0.18f * presence), style = orbitGlowStroke)
                            drawPath(
                                orbitFront[k],
                                lerp(tint, Color.White, 0.35f).copy(alpha = 0.9f * presence),
                                style = if (o.dotted) orbitDotted else orbitSolid,
                            )
                            for (j in 0 until o.sparkles) {
                                val theta = o.phase + j * (2f * PI.toFloat() / o.sparkles) + spin * o.speed * 0.0021f
                                val pt = orbitPoint(o, theta, spin, center, radius)
                                val visible = pt.z >= 0f || !insideDisk(pt.x, pt.y, center, radius)
                                if (!visible) continue
                                drawCircle(sparkleColor.copy(alpha = 0.30f * presence), radius = dot * 2.2f, center = Offset(pt.x, pt.y))
                                drawCircle(Color.White.copy(alpha = presence), radius = dot * 0.6f, center = Offset(pt.x, pt.y))
                            }
                        }
                    }

                    // ---- connected ripple
                    val rp = ripple.value
                    if (rp < 1f && p == OrbPhase.Connected) {
                        drawCircle(
                            tint.copy(alpha = (1f - rp) * 0.6f),
                            radius = radius * (1f + 0.25f * rp),
                            center = center,
                            style = Stroke((1f - rp) * 6.dp.toPx() + 1f),
                        )
                    }

                    // ---- gaming HUD and activation burst
                    val h = hud.value
                    if (h > 0.001f) drawBrackets(center, radius, h, c.accent, c.accentHot, bracket, t, reduced)
                    val b = boost.value
                    if (b < 1f && gamingNow) drawBoost(center, radius, b, c.accent, c.accentHot, speedLine)
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        GlobeLabel(label, phase, tint, Modifier.align(Alignment.BottomCenter))
        if (gaming) GamingOverlay(gamingTitle, hudText, boost, hud)
    }
}

@Composable
private fun GlobeLabel(label: String, phase: OrbPhase, tint: Color, modifier: Modifier) {
    val c = ZeroTheme.colors
    Box(
        modifier
            .padding(bottom = 2.dp)
            .background(c.bg.copy(alpha = 0.78f), RoundedCornerShape(50))
            .border(1.dp, tint.copy(alpha = 0.6f), RoundedCornerShape(50))
            .padding(horizontal = 18.dp, vertical = 7.dp),
    ) {
        Text(
            text = label,
            color = when (phase) {
                OrbPhase.Idle -> c.text
                else -> tint
            },
            style = MaterialTheme.typography.titleSmall.copy(
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
                letterSpacing = latinTracking(0.16),
            ),
            textAlign = TextAlign.Center,
            maxLines = 1,
        )
    }
}

/** "GAME MODE" slam during the burst, then the HUD's corner readouts. */
@Composable
private fun androidx.compose.foundation.layout.BoxScope.GamingOverlay(
    title: String,
    hudText: String?,
    boost: Animatable<Float, *>,
    hud: Animatable<Float, *>,
) {
    val c = ZeroTheme.colors
    Text(
        title,
        color = c.accentHot,
        style = MaterialTheme.typography.headlineMedium.copy(
            fontWeight = FontWeight.Black,
            letterSpacing = latinTracking(0.22),
        ),
        maxLines = 1,
        modifier = Modifier
            .align(Alignment.Center)
            .graphicsLayer {
                val p = boost.value
                if (p >= 1f) {
                    alpha = 0f
                    return@graphicsLayer
                }
                val land = (p / 0.22f).coerceIn(0f, 1f)
                val s = 1.9f - 0.9f * easeOutBack(land)
                scaleX = s; scaleY = s
                alpha = when {
                    p < 0.05f -> p / 0.05f
                    p > 0.78f -> ((1f - p) / 0.22f).coerceIn(0f, 1f)
                    else -> 1f
                }
                val shake = (1f - p) * (1f - p)
                translationX = sin(p * 90f) * shake * 10.dp.toPx()
                translationY = cos(p * 70f) * shake * 3.dp.toPx()
            },
    )
    if (hudText != null) {
        Text(
            hudText,
            color = c.accent,
            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold, letterSpacing = latinTracking(0.12)),
            modifier = Modifier
                .align(Alignment.TopEnd)
                // Above the HUD frame: at the box's top edge it sat right on
                // the corner bracket's line.
                .offset(y = (-26).dp)
                .padding(end = 4.dp)
                .graphicsLayer { alpha = hud.value.coerceIn(0f, 1f) },
        )
    }
}

// --------------------------------------------------------------- geometry

/** A great-circle route, lifted off the surface in the middle. */
private class Route(val to: LatLon, val xyz: FloatArray, val center: LatLon)

private fun buildRoute(from: LatLon, dest: LatLon): Route {
    val a = unitVector(from.lat, from.lon)
    val b = unitVector(dest.lat, dest.lon)
    val dot = (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]).coerceIn(-1f, 1f)
    val omega = acos(dot)
    val lift = 0.05f + 0.16f * omega / PI.toFloat()
    val xyz = FloatArray(ARC_POINTS * 3)
    for (i in 0 until ARC_POINTS) {
        val t = i / (ARC_POINTS - 1f)
        val (wa, wb) = if (omega < 1e-4f) {
            (1f - t) to t
        } else {
            val s = sin(omega)
            sin((1f - t) * omega) / s to sin(t * omega) / s
        }
        var x = wa * a[0] + wb * b[0]
        var y = wa * a[1] + wb * b[1]
        var z = wa * a[2] + wb * b[2]
        val len = sqrt(x * x + y * y + z * z).coerceAtLeast(1e-6f)
        val h = (1f + lift * sin(PI.toFloat() * t)) / len
        x *= h; y *= h; z *= h
        xyz[i * 3] = x; xyz[i * 3 + 1] = y; xyz[i * 3 + 2] = z
    }
    val mid = floatArrayOf(a[0] + b[0], a[1] + b[1], a[2] + b[2])
    val center = if (mid[0] * mid[0] + mid[1] * mid[1] + mid[2] * mid[2] < 1e-4f) from else latLonOf(mid)
    return Route(dest, xyz, center)
}

/** Project polylines into a front and a back path. */
private fun project(
    lines: SpherePolylines,
    cam: GlobeCamera,
    center: Offset,
    radius: Float,
    front: Path,
    back: Path,
) {
    front.rewind(); back.rewind()
    val xyz = lines.xyz
    for (l in 0 until lines.lineCount) {
        var side = 0 // 1 front, -1 back, 0 none yet
        for (i in lines.starts[l] until lines.starts[l + 1]) {
            val x = xyz[i * 3]; val y = xyz[i * 3 + 1]; val z = xyz[i * 3 + 2]
            val sx = x * cam.ex + y * cam.ey + z * cam.ez
            val sy = x * cam.nx + y * cam.ny + z * cam.nz
            val depth = x * cam.vx + y * cam.vy + z * cam.vz
            val px = center.x + sx * radius
            val py = center.y - sy * radius
            if (depth >= 0f) {
                if (side == 1) front.lineTo(px, py) else front.moveTo(px, py)
                side = 1
            } else {
                if (side == -1) back.lineTo(px, py) else back.moveTo(px, py)
                side = -1
            }
        }
    }
}

/** The part of the route between fractions [from] and [to], skipping what is hidden behind the globe. */
private fun arcSegment(route: Route, cam: GlobeCamera, center: Offset, radius: Float, from: Float, to: Float, out: Path) {
    out.rewind()
    if (to <= from) return
    val xyz = route.xyz
    val last = ARC_POINTS - 1
    val start = from * last
    val end = to * last
    var drawing = false
    var i = start
    while (true) {
        val k = i.coerceAtMost(end)
        val lo = k.toInt().coerceIn(0, last)
        val hi = (lo + 1).coerceAtMost(last)
        val f = k - lo
        val x = xyz[lo * 3] + (xyz[hi * 3] - xyz[lo * 3]) * f
        val y = xyz[lo * 3 + 1] + (xyz[hi * 3 + 1] - xyz[lo * 3 + 1]) * f
        val z = xyz[lo * 3 + 2] + (xyz[hi * 3 + 2] - xyz[lo * 3 + 2]) * f
        val sx = x * cam.ex + y * cam.ey + z * cam.ez
        val sy = x * cam.nx + y * cam.ny + z * cam.nz
        val depth = x * cam.vx + y * cam.vy + z * cam.vz
        // Lifted points behind the globe are still visible outside its silhouette.
        val visible = depth >= 0f || sx * sx + sy * sy > 1f
        val px = center.x + sx * radius
        val py = center.y - sy * radius
        if (visible) {
            if (drawing) out.lineTo(px, py) else out.moveTo(px, py)
            drawing = true
        } else {
            drawing = false
        }
        if (k >= end) break
        i = (k.toInt() + 1).toFloat()
    }
}

/** A small circle of angular radius [degrees] around [at], front side only. */
private fun radarRing(at: LatLon, degrees: Float, cam: GlobeCamera, center: Offset, radius: Float, out: Path) {
    out.rewind()
    val u = unitVector(at.lat, at.lon)
    // A tangent basis at u.
    val ax = if (kotlin.math.abs(u[2]) < 0.9f) 0f else 1f
    val az = if (kotlin.math.abs(u[2]) < 0.9f) 1f else 0f
    var t1x = 0f * u[2] - az * u[1]
    var t1y = az * u[0] - ax * u[2]
    var t1z = ax * u[1] - 0f * u[0]
    val n1 = sqrt(t1x * t1x + t1y * t1y + t1z * t1z).coerceAtLeast(1e-6f)
    t1x /= n1; t1y /= n1; t1z /= n1
    val t2x = u[1] * t1z - u[2] * t1y
    val t2y = u[2] * t1x - u[0] * t1z
    val t2z = u[0] * t1y - u[1] * t1x
    val r = degrees * (PI.toFloat() / 180f)
    val cr = cos(r); val sr = sin(r)
    var drawing = false
    for (k in 0..RADAR_POINTS) {
        val th = k * 2f * PI.toFloat() / RADAR_POINTS
        val ct = cos(th); val st = sin(th)
        val x = cr * u[0] + sr * (ct * t1x + st * t2x)
        val y = cr * u[1] + sr * (ct * t1y + st * t2y)
        val z = cr * u[2] + sr * (ct * t1z + st * t2z)
        val depth = x * cam.vx + y * cam.vy + z * cam.vz
        if (depth < 0f) { drawing = false; continue }
        val px = center.x + (x * cam.ex + y * cam.ey + z * cam.ez) * radius
        val py = center.y - (x * cam.nx + y * cam.ny + z * cam.nz) * radius
        if (drawing) out.lineTo(px, py) else out.moveTo(px, py)
        drawing = true
    }
}

private fun DrawScope.drawEndpoint(at: LatLon, cam: GlobeCamera, center: Offset, radius: Float, color: Color, dot: Float, pulse: Float) {
    val u = unitVector(at.lat, at.lon)
    val depth = u[0] * cam.vx + u[1] * cam.vy + u[2] * cam.vz
    if (depth < 0f) return
    val pos = Offset(
        center.x + (u[0] * cam.ex + u[1] * cam.ey + u[2] * cam.ez) * radius,
        center.y - (u[0] * cam.nx + u[1] * cam.ny + u[2] * cam.nz) * radius,
    )
    val fade = (depth * 3f).coerceIn(0f, 1f)
    drawCircle(color.copy(alpha = 0.25f * fade), radius = dot * 2.8f, center = pos)
    if (pulse > 0f) drawCircle(color.copy(alpha = (1f - pulse) * 0.8f * fade), radius = dot + dot * 3.5f * pulse, center = pos, style = Stroke(dot * 0.45f))
    drawCircle(Color.White.copy(alpha = fade), radius = dot * 0.55f, center = pos)
    drawCircle(color.copy(alpha = fade), radius = dot, center = pos, style = Stroke(dot * 0.5f))
}

/** HUD corner brackets: they snap in from outside and breathe slightly. */
private fun DrawScope.drawBrackets(center: Offset, radius: Float, h: Float, a: Color, b: Color, stroke: Stroke, t: Float, reduced: Boolean) {
    val breathe = if (reduced) 0f else 0.012f * sin(t / 900f)
    val half = radius * (1.12f + (1f - h) * 0.35f + breathe)
    val len = radius * 0.22f
    val alpha = h.coerceIn(0f, 1f)
    val corners = arrayOf(-1f to -1f, 1f to -1f, -1f to 1f, 1f to 1f)
    corners.forEachIndexed { i, (sx, sy) ->
        val x = center.x + sx * half
        val y = center.y + sy * half
        val color = (if (i % 3 == 0) a else b).copy(alpha = alpha)
        drawLine(color, Offset(x, y), Offset(x - sx * len, y), strokeWidth = stroke.width, cap = StrokeCap.Square)
        drawLine(color, Offset(x, y), Offset(x, y - sy * len), strokeWidth = stroke.width, cap = StrokeCap.Square)
    }
    // Tick marks on the rim, like a scope.
    for (k in 0 until 24) {
        val ang = k * (2f * PI.toFloat() / 24f) + (if (reduced) 0f else t / 6000f)
        val r0 = radius * 1.04f
        val r1 = radius * (if (k % 6 == 0) 1.10f else 1.07f)
        drawLine(
            a.copy(alpha = alpha * 0.45f),
            Offset(center.x + cos(ang) * r0, center.y + sin(ang) * r0),
            Offset(center.x + cos(ang) * r1, center.y + sin(ang) * r1),
            strokeWidth = stroke.width * 0.6f,
        )
    }
}

/** The gaming activation burst: flash, two shockwaves, warp lines and a scanline. */
private fun DrawScope.drawBoost(center: Offset, radius: Float, p: Float, a: Color, b: Color, line: Stroke) {
    val far = radius * 6f
    // Flash.
    if (p < 0.12f) drawCircle(Color.White.copy(alpha = 0.28f * (1f - p / 0.12f)), radius = far, center = center)
    // Shockwaves.
    for ((delayAt, color) in listOf(0f to b, 0.12f to a)) {
        val q = ((p - delayAt) / 0.55f).coerceIn(0f, 1f)
        if (q <= 0f || q >= 1f) continue
        val e = EaseOutCubic.transform(q)
        drawCircle(
            color.copy(alpha = (1f - q) * 0.9f),
            radius = radius * (1f + 4.2f * e),
            center = center,
            style = Stroke((1f - q) * 16.dp.toPx() + 1.dp.toPx()),
        )
    }
    // Warp lines.
    val w = (p / 0.8f).coerceIn(0f, 1f)
    if (w < 1f) {
        val e = EaseOutCubic.transform(w)
        for (i in 0 until 36) {
            val ang = (i * 10f + (i * 37 % 11)) * PI.toFloat() / 180f
            val r0 = radius * (1.05f + 3.6f * e) * (0.85f + (i * 13 % 7) * 0.05f)
            val len = radius * 0.7f * (1f - w)
            drawLine(
                (if (i % 2 == 0) a else b).copy(alpha = (1f - w) * 0.9f),
                Offset(center.x + cos(ang) * r0, center.y + sin(ang) * r0),
                Offset(center.x + cos(ang) * (r0 + len), center.y + sin(ang) * (r0 + len)),
                strokeWidth = line.width,
                cap = StrokeCap.Round,
            )
        }
    }
    // Scanline sweeping down through the globe.
    val s = ((p - 0.08f) / 0.6f).coerceIn(0f, 1f)
    if (s > 0f && s < 1f) {
        val y = center.y - radius * 1.6f + s * radius * 3.2f
        val band = radius * 0.18f
        drawRect(
            Brush.verticalGradient(
                0f to Color.Transparent,
                0.5f to a.copy(alpha = 0.45f * (1f - s)),
                1f to Color.Transparent,
                startY = y - band,
                endY = y + band,
            ),
            topLeft = Offset(center.x - far, y - band),
            size = androidx.compose.ui.geometry.Size(far * 2f, band * 2f),
        )
    }
}

/** A jittery, deterministic offset in [-1, 1] that jumps ~20 times over the burst. */
private fun glitchOffset(p: Float): Float {
    val step = (p * 40f).toInt()
    val hash = (step * 1103515245 + 12345) and 0x7fffffff
    return (hash % 2001) / 1000f - 1f
}

private fun easeOutBack(t: Float): Float {
    val c1 = 1.70158f
    val c3 = c1 + 1f
    val u = t - 1f
    return 1f + c3 * u * u * u + c1 * u * u
}

private val EaseOutCubic = androidx.compose.animation.core.Easing { t -> 1f - (1f - t) * (1f - t) * (1f - t) }
private val EaseInOutCubic = androidx.compose.animation.core.Easing { t ->
    if (t < 0.5f) 4f * t * t * t else 1f - (-2f * t + 2f).let { it * it * it } / 2f
}

// ------------------------------------------------------------------ orbits

/** One orbit ring: radius (× globe), tilt, where it starts, how fast it spins. */
private class Orbit(
    val radius: Float,
    val tiltDeg: Float,
    val nodeDeg: Float,
    val speed: Float,
    val dotted: Boolean,
    val sparkles: Int,
    val phase: Float,
)

private val ORBITS = arrayOf(
    Orbit(1.16f, 72f, 18f, 1.0f, dotted = false, sparkles = 2, phase = 0.4f),
    Orbit(1.24f, 64f, -52f, -0.7f, dotted = true, sparkles = 3, phase = 1.9f),
    Orbit(1.20f, 80f, 115f, 0.85f, dotted = false, sparkles = 2, phase = 3.1f),
    Orbit(1.30f, 58f, 160f, -0.55f, dotted = true, sparkles = 2, phase = 5.0f),
)

private data class ScreenPoint(val x: Float, val y: Float, val z: Float)

/**
 * A point of an orbit in view space: a circle in the horizontal plane, tilted
 * about the view's x axis, then turned about the vertical axis by its node
 * angle plus the spin. z is toward the viewer.
 */
private fun orbitPoint(o: Orbit, theta: Float, spin: Float, center: Offset, radius: Float): ScreenPoint {
    val rad = PI.toFloat() / 180f
    val tilt = o.tiltDeg * rad
    val node = o.nodeDeg * rad + spin * o.speed * 0.0009f
    // Circle in the x/z plane.
    val cx = cos(theta) * o.radius
    val cz = sin(theta) * o.radius
    // Tilt about x: y and z mix.
    val y = -cz * cos(tilt)
    val z1 = cz * sin(tilt)
    // Turn about the vertical (y) axis.
    val x = cx * cos(node) + z1 * sin(node)
    val z = -cx * sin(node) + z1 * cos(node)
    return ScreenPoint(center.x + x * radius, center.y - y * radius, z)
}

private fun insideDisk(x: Float, y: Float, center: Offset, radius: Float): Boolean {
    val dx = x - center.x; val dy = y - center.y
    return dx * dx + dy * dy < radius * radius
}

/** Split every orbit into what passes in front of the globe and what goes behind it. */
private fun orbitPaths(center: Offset, radius: Float, spin: Float, front: Array<Path>, back: Array<Path>) {
    val steps = 120
    for (k in ORBITS.indices) {
        val o = ORBITS[k]
        front[k].rewind(); back[k].rewind()
        var side = 0
        for (i in 0..steps) {
            val theta = i * 2f * PI.toFloat() / steps
            val p = orbitPoint(o, theta, spin, center, radius)
            // Behind the globe only where the globe actually covers it.
            val hidden = p.z < 0f && insideDisk(p.x, p.y, center, radius)
            if (!hidden) {
                if (side == 1) front[k].lineTo(p.x, p.y) else front[k].moveTo(p.x, p.y)
                side = 1
            } else {
                if (side == -1) back[k].lineTo(p.x, p.y) else back[k].moveTo(p.x, p.y)
                side = -1
            }
        }
    }
}

/** A small arrowhead at fraction [at] of the route, pointing the way it travels. */
private fun DrawScope.drawArrowHead(route: Route, cam: GlobeCamera, center: Offset, radius: Float, at: Float, color: Color, size: Float, path: Path) {
    fun screen(f: Float): ScreenPoint {
        val last = ARC_POINTS - 1
        val k = (f.coerceIn(0f, 1f) * last)
        val lo = k.toInt().coerceIn(0, last)
        val hi = (lo + 1).coerceAtMost(last)
        val fr = k - lo
        val xyz = route.xyz
        val x = xyz[lo * 3] + (xyz[hi * 3] - xyz[lo * 3]) * fr
        val y = xyz[lo * 3 + 1] + (xyz[hi * 3 + 1] - xyz[lo * 3 + 1]) * fr
        val z = xyz[lo * 3 + 2] + (xyz[hi * 3 + 2] - xyz[lo * 3 + 2]) * fr
        val sx = x * cam.ex + y * cam.ey + z * cam.ez
        val sy = x * cam.nx + y * cam.ny + z * cam.nz
        val depth = x * cam.vx + y * cam.vy + z * cam.vz
        val visible = depth >= 0f || sx * sx + sy * sy > 1f
        return ScreenPoint(center.x + sx * radius, center.y - sy * radius, if (visible) 1f else -1f)
    }
    val tip = screen(at)
    if (tip.z < 0f) return
    val tail = screen(at - 0.02f)
    var dx = tip.x - tail.x
    var dy = tip.y - tail.y
    val len = sqrt(dx * dx + dy * dy)
    if (len < 0.5f) return
    dx /= len; dy /= len
    // Perpendicular.
    val px = -dy; val py = dx
    path.rewind()
    path.moveTo(tip.x + dx * size * 0.6f, tip.y + dy * size * 0.6f)
    path.lineTo(tip.x - dx * size * 0.6f + px * size * 0.55f, tip.y - dy * size * 0.6f + py * size * 0.55f)
    path.lineTo(tip.x - dx * size * 0.25f, tip.y - dy * size * 0.25f)
    path.lineTo(tip.x - dx * size * 0.6f - px * size * 0.55f, tip.y - dy * size * 0.6f - py * size * 0.55f)
    path.close()
    drawCircle(color.copy(alpha = 0.35f), radius = size * 0.9f, center = Offset(tip.x, tip.y))
    drawPath(path, color)
}
