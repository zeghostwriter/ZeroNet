package com.zeronet.mobile.ui.update

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.BuildConfig
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.Motion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatBytes
import com.zeronet.mobile.ui.util.ltr
import com.zeronet.mobile.update.ReleaseInfo
import com.zeronet.mobile.update.UpdateState
import kotlin.math.PI
import kotlin.math.sin
import kotlinx.coroutines.delay

/** What the update sheet's buttons do. */
class UpdateActions(
    val onUpdate: () -> Unit,
    val onLater: () -> Unit,
    val onCancel: () -> Unit,
    val onInstall: () -> Unit,
    val onOpenPage: (String) -> Unit,
    /** Whether Android already lets ZeroNet install apps. */
    val canInstall: () -> Boolean,
)

/** Which face the sheet shows; the animations key off it. */
private enum class Phase { Offer, Downloading, Ready, Reinstall, Failed }

private fun UpdateState.phase(): Phase? = when (this) {
    is UpdateState.Available -> Phase.Offer
    is UpdateState.Downloading -> Phase.Downloading
    is UpdateState.Ready -> Phase.Ready
    is UpdateState.NeedsReinstall -> Phase.Reinstall
    is UpdateState.Failed -> Phase.Failed
    else -> null
}

private fun UpdateState.release(): ReleaseInfo? = when (this) {
    is UpdateState.Available -> release
    is UpdateState.Downloading -> release
    is UpdateState.Ready -> release
    is UpdateState.NeedsReinstall -> release
    is UpdateState.Failed -> release
    else -> null
}

/**
 * The update sheet: an animated emblem (a comet circling while there is
 * news, the progress ring while downloading, a check once ready), the
 * version change, what's new, and one clear next step.
 */
@Composable
fun UpdateSheet(visible: Boolean, state: UpdateState, actions: UpdateActions) {
    val release = state.release()
    val phase = state.phase()
    ZeroSheet(
        visible = visible && release != null && phase != null,
        onDismiss = actions.onLater,
        title = stringResource(R.string.update_sheet_title),
    ) {
        if (release == null || phase == null) return@ZeroSheet
        val c = ZeroTheme.colors
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Motion specs are read here: transition lambdas are not composable.
            val slide = Motion.standard<androidx.compose.ui.unit.IntOffset>()
            Spacer(Modifier.height(4.dp))
            UpdateEmblem(phase, (state as? UpdateState.Downloading)?.fraction ?: 0f)
            Spacer(Modifier.height(18.dp))

            AnimatedContent(
                targetState = phase,
                transitionSpec = {
                    (fadeIn(tween(ZeroMotion.ms(260))) + slideInVertically(slide) { it / 3 }) togetherWith
                        fadeOut(tween(ZeroMotion.ms(120)))
                },
                label = "update-title",
            ) { p ->
                val locale = currentLocale()
                val v = ltr(Num.localize(release.version, locale))
                Text(
                    when (p) {
                        Phase.Offer -> stringResource(R.string.update_title_available, v)
                        Phase.Downloading -> stringResource(R.string.update_title_downloading, v)
                        Phase.Ready -> stringResource(R.string.update_title_ready, v)
                        Phase.Reinstall -> stringResource(R.string.update_title_reinstall)
                        Phase.Failed -> stringResource(R.string.update_title_failed)
                    },
                    style = MaterialTheme.typography.titleLarge,
                    color = c.text,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().semantics { heading() },
                )
            }
            Spacer(Modifier.height(10.dp))
            VersionPill(release.version, done = phase == Phase.Ready)
            Spacer(Modifier.height(16.dp))

            AnimatedContent(
                targetState = phase,
                transitionSpec = { fadeIn(tween(ZeroMotion.ms(220))) togetherWith fadeOut(tween(ZeroMotion.ms(120))) },
                label = "update-body",
            ) { p ->
                Column(Modifier.fillMaxWidth()) {
                    when (p) {
                        Phase.Offer -> OfferBody(release)
                        Phase.Downloading -> DownloadBody(state as? UpdateState.Downloading)
                        Phase.Ready -> Hint(stringResource(if (actions.canInstall()) R.string.update_ready_hint else R.string.update_allow_hint))
                        Phase.Reinstall -> Hint(stringResource(R.string.update_reinstall_body), c.warn)
                        Phase.Failed -> Hint((state as? UpdateState.Failed)?.message.orEmpty(), c.err)
                    }
                }
            }
            Spacer(Modifier.height(20.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                when (phase) {
                    Phase.Offer -> {
                        TonalButton(stringResource(R.string.update_later), actions.onLater, Modifier.weight(1f))
                        PrimaryButton(stringResource(R.string.update_now), actions.onUpdate, Modifier.weight(1.4f), icon = ZeroIcons.ArrowDown)
                    }
                    Phase.Downloading -> {
                        TonalButton(stringResource(R.string.update_cancel), actions.onCancel, Modifier.weight(1f))
                        PrimaryButton(stringResource(R.string.update_install), {}, Modifier.weight(1.4f), enabled = false, loading = true)
                    }
                    Phase.Ready -> {
                        TonalButton(stringResource(R.string.update_later), actions.onLater, Modifier.weight(1f))
                        PrimaryButton(
                            stringResource(if (actions.canInstall()) R.string.update_install else R.string.update_allow),
                            actions.onInstall,
                            Modifier.weight(1.4f),
                            icon = ZeroIcons.Check,
                            container = c.ok,
                        )
                    }
                    Phase.Reinstall -> {
                        TonalButton(stringResource(R.string.update_later), actions.onLater, Modifier.weight(1f))
                        PrimaryButton(stringResource(R.string.update_open_page), { actions.onOpenPage(release.page) }, Modifier.weight(1.4f), icon = ZeroIcons.External)
                    }
                    Phase.Failed -> {
                        TonalButton(stringResource(R.string.update_later), actions.onLater, Modifier.weight(1f))
                        PrimaryButton(stringResource(R.string.update_retry), actions.onUpdate, Modifier.weight(1.4f), icon = ZeroIcons.Refresh)
                    }
                }
            }
        }
    }
}

/**
 * The emblem. A soft glow breathes behind it; around it, a comet circles
 * while an update waits, the ring fills as it downloads and closes in the
 * ok colour once the file is ready; in the middle an arrow bobs, then the
 * percentage counts up, then a check pops in.
 */
@Composable
private fun UpdateEmblem(phase: Phase, fraction: Float) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val infinite = rememberInfiniteTransition(label = "update-emblem")
    val breath by infinite.animateFloat(
        0f, 1f,
        infiniteRepeatable(tween(ZeroMotion.BREATH_PERIOD_MS.toInt() / 2, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "breath",
    )
    val spin by infinite.animateFloat(0f, 360f, infiniteRepeatable(tween(ZeroMotion.ms(2200), easing = LinearEasing)), label = "spin")
    val bob by infinite.animateFloat(0f, 1f, infiniteRepeatable(tween(ZeroMotion.ms(1400), easing = LinearEasing)), label = "bob")

    val shown by animateFloatAsState(fraction, Motion.standard(), label = "progress")
    val ringColor by animateColorAsState(
        when (phase) {
            Phase.Ready -> c.ok
            Phase.Reinstall -> c.warn
            Phase.Failed -> c.err
            else -> c.accent
        },
        tween(ZeroMotion.ms(420)),
        label = "ring",
    )
    val full by animateFloatAsState(if (phase == Phase.Ready || phase == Phase.Reinstall || phase == Phase.Failed) 1f else 0f, Motion.expressive(), label = "full")

    val pop = Motion.expressive<Float>()
    Box(Modifier.size(132.dp), contentAlignment = Alignment.Center) {
        // Glow.
        Box(
            Modifier
                .size(132.dp)
                .graphicsLayer {
                    val s = if (reduced) 1f else 0.9f + 0.1f * breath
                    scaleX = s
                    scaleY = s
                    alpha = if (reduced) 0.7f else 0.55f + 0.35f * breath
                }
                .background(Brush.radialGradient(listOf(ringColor.copy(alpha = 0.32f), Color.Transparent)), CircleShape),
        )
        // Ring.
        Box(
            Modifier.size(96.dp).drawBehind {
                val stroke = 4.dp.toPx()
                val inset = stroke / 2
                val arc = Size(size.width - stroke, size.height - stroke)
                drawArc(c.border, 0f, 360f, false, Offset(inset, inset), arc, style = Stroke(stroke))
                when {
                    phase == Phase.Downloading -> drawArc(
                        Brush.sweepGradient(listOf(c.accentDim, c.accentBright, c.accentDim)),
                        -90f, 360f * shown, false, Offset(inset, inset), arc,
                        style = Stroke(stroke, cap = StrokeCap.Round),
                    )
                    full > 0.01f -> drawArc(ringColor, -90f, 360f * full.coerceAtMost(1f), false, Offset(inset, inset), arc, style = Stroke(stroke, cap = StrokeCap.Round))
                    else -> rotate(if (reduced) 0f else spin) {
                        drawArc(
                            Brush.sweepGradient(0f to Color.Transparent, 0.7f to c.accent.copy(alpha = 0.2f), 1f to c.accentBright),
                            0f, 300f, false, Offset(inset, inset), arc,
                            style = Stroke(stroke, cap = StrokeCap.Round),
                        )
                    }
                }
            },
        )
        // Centre.
        AnimatedContent(
            targetState = phase,
            transitionSpec = { (fadeIn(tween(ZeroMotion.ms(200))) + scaleIn(pop, initialScale = 0.6f)) togetherWith fadeOut(tween(ZeroMotion.ms(120))) },
            label = "update-centre",
        ) { p ->
            Box(Modifier.size(72.dp).clip(CircleShape).background(ringColor.copy(alpha = 0.14f)), contentAlignment = Alignment.Center) {
                when (p) {
                    Phase.Offer -> Icon(
                        ZeroIcons.ArrowDown, null, tint = c.accent,
                        modifier = Modifier.size(34.dp).graphicsLayer {
                            translationY = if (reduced) 0f else sin(bob * 2 * PI).toFloat() * 4.dp.toPx()
                        },
                    )
                    Phase.Downloading -> {
                        val locale = currentLocale()
                        Text(
                            Num.localize("${(shown * 100).toInt()}%", locale),
                            style = MaterialTheme.typography.titleMedium,
                            color = c.accentBright,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                        )
                    }
                    Phase.Ready -> Icon(ZeroIcons.Check, null, tint = c.ok, modifier = Modifier.size(36.dp))
                    Phase.Reinstall, Phase.Failed -> Icon(ZeroIcons.Info, null, tint = ringColor, modifier = Modifier.size(32.dp))
                }
            }
        }
    }
}

/** "0.1.4 → 0.1.5", the arrow pulsing towards the new version. */
@Composable
private fun VersionPill(version: String, done: Boolean) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val reduced = LocalReducedMotion.current
    val pulse by rememberInfiniteTransition(label = "pill").animateFloat(
        0f, 1f, infiniteRepeatable(tween(ZeroMotion.ms(1200), easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "pulse",
    )
    val accent by animateColorAsState(if (done) c.ok else c.accent, tween(ZeroMotion.ms(420)), label = "pill-accent")
    // The arrow nudges towards the new version, which is leftwards in Persian.
    val towards = if (androidx.compose.ui.platform.LocalLayoutDirection.current == androidx.compose.ui.unit.LayoutDirection.Rtl) -1f else 1f
    Row(
        Modifier.clip(RoundedCornerShape(50)).background(c.surfaceHi).padding(horizontal = 14.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(ltr(Num.localize(BuildConfig.VERSION_NAME, locale)), style = MaterialTheme.typography.labelLarge, color = c.muted)
        Icon(
            ZeroIcons.ChevronEnd, null, tint = accent,
            modifier = Modifier.padding(horizontal = 6.dp).size(16.dp).graphicsLayer {
                translationX = if (reduced || done) 0f else pulse * 3.dp.toPx() * towards
                alpha = if (reduced) 1f else 0.6f + 0.4f * pulse
            },
        )
        Text(ltr(Num.localize(version, locale)), style = MaterialTheme.typography.labelLarge, color = accent)
    }
}

@Composable
private fun OfferBody(release: ReleaseInfo) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    if (release.notes.isNotEmpty()) {
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(c.surfaceHi).padding(16.dp),
        ) {
            Text(stringResource(R.string.update_whats_new), style = MaterialTheme.typography.labelLarge, color = c.muted)
            Spacer(Modifier.height(8.dp))
            release.notes.forEachIndexed { i, note -> NoteLine(note, i) }
        }
        Spacer(Modifier.height(12.dp))
    }
    if (release.apkSize > 0) {
        Hint(stringResource(R.string.update_size, formatBytes(context, release.apkSize, locale)))
    }
}

/** One release note, arriving a beat after the one above it. */
@Composable
private fun NoteLine(note: String, index: Int) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    var shown by remember { mutableStateOf(reduced) }
    LaunchedEffect(Unit) {
        delay(ZeroMotion.ms(80 + 60 * index).toLong())
        shown = true
    }
    AnimatedVisibility(
        visible = shown,
        enter = fadeIn(tween(ZeroMotion.ms(260))) + slideInVertically(Motion.standard()) { it / 2 },
    ) {
        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Box(Modifier.padding(top = 8.dp).size(6.dp).clip(CircleShape).background(c.accent))
            Spacer(Modifier.width(10.dp))
            Text(note, style = MaterialTheme.typography.bodyMedium, color = c.text)
        }
    }
}

@Composable
private fun DownloadBody(state: UpdateState.Downloading?) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val fraction = state?.fraction ?: 0f
    ShimmerBar(fraction)
    Spacer(Modifier.height(10.dp))
    if (state != null && state.total > 0) {
        Text(
            stringResource(R.string.update_progress, formatBytes(context, state.received, locale), formatBytes(context, state.total, locale)),
            style = MaterialTheme.typography.bodyMedium,
            color = c.muted,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** A slim progress bar with a highlight gliding along its filled part. */
@Composable
private fun ShimmerBar(fraction: Float) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val shown by animateFloatAsState(fraction, Motion.standard(), label = "bar")
    val sheen by rememberInfiniteTransition(label = "sheen").animateFloat(
        -0.3f, 1.3f, infiniteRepeatable(tween(ZeroMotion.ms(1500), easing = LinearEasing)), label = "sheen-x",
    )
    Box(
        Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(50)).background(c.surfaceHi),
    ) {
        Box(
            Modifier
                .fillMaxWidth(shown.coerceIn(0f, 1f))
                .fillMaxHeight()
                .clip(RoundedCornerShape(50))
                .background(Brush.horizontalGradient(listOf(c.accentDim, c.accentBright)))
                .drawWithContent {
                    drawContent()
                    if (!reduced) {
                        val x = size.width * sheen
                        val w = size.width * 0.25f
                        drawRect(
                            Brush.horizontalGradient(
                                listOf(Color.Transparent, Color.White.copy(alpha = 0.45f), Color.Transparent),
                                startX = x - w, endX = x + w,
                            ),
                        )
                    }
                },
        )
    }
}

@Composable
private fun Hint(text: String, color: Color = ZeroTheme.colors.muted) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = color, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
}
