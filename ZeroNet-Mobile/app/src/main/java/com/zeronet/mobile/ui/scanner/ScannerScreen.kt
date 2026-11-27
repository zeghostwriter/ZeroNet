package com.zeronet.mobile.ui.scanner

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.ui.components.CardShape
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.home.rememberAmbientClock
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.shell.LargeTitle
import com.zeronet.mobile.ui.shell.LocalBottomBarSpace
import com.zeronet.mobile.ui.shell.ScreenTopBar
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.Motion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatDelay
import androidx.compose.ui.platform.LocalContext
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.rememberHazeState

/** How many of the best results "Copy top N" takes. */
private const val COPY_BEST = 10

@Immutable
data class ScannerActions(
    val onStart: () -> Unit = {},
    val onStop: () -> Unit = {},
    val onCopy: (ScanResult) -> Unit = {},
    val onCopyAll: (List<ScanResult>) -> Unit = {},
)

@Composable
fun ScannerScreen(state: ScanState, actions: ScannerActions, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val resources = androidx.compose.ui.platform.LocalResources.current
    val locale = currentLocale()
    val haze = rememberHazeState()
    val listState = rememberLazyListState()
    val scrolled by remember { derivedStateOf { listState.firstVisibleItemIndex > 0 || listState.firstVisibleItemScrollOffset > 8 } }
    val sorted = remember(state.results) { state.results.sortedBy { it.rttMs } }
    val best = sorted.firstOrNull()?.rttMs ?: -1
    val status = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()

    Box(modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().hazeSource(haze),
            contentPadding = PaddingValues(top = status + 56.dp, bottom = LocalBottomBarSpace.current + 24.dp),
        ) {
            item(key = "title", contentType = "title") {
                LargeTitle(stringResource(R.string.tab_scanner), subtitle = stringResource(R.string.scanner_explainer))
            }
            item(key = "hero", contentType = "hero") {
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    val fraction = if (state.total > 0) state.scanned.toFloat() / state.total else 0f
                    ScanRing(
                        progress = fraction,
                        running = state.running,
                        modifier = Modifier.size(220.dp).semantics {
                            contentDescription = resources.getString(R.string.scanner_progress_description)
                            stateDescription = if (state.running) {
                                resources.getString(R.string.scanner_progress_state, Num.int((fraction * 100).toInt(), locale))
                            } else {
                                resources.getString(R.string.scanner_ready)
                            }
                        },
                    ) {
                        val center = when {
                            state.running || state.scanned > 0 -> Num.int((fraction * 100).toInt().coerceIn(0, 100), locale) + if (Num.isPersian(locale)) "٪" else "%"
                            else -> stringResource(R.string.scanner_ready)
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(center, style = MaterialTheme.typography.displaySmall, color = if (state.running) c.accent else c.text)
                            Text(
                                stringResource(if (state.running) R.string.scanner_scanning else if (state.scanned > 0) R.string.scanner_done else R.string.scanner_idle_hint),
                                style = MaterialTheme.typography.bodySmall,
                                color = c.muted,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                    Spacer(Modifier.height(20.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Counter(stringResource(R.string.scanner_scanned), Num.grouped(state.scanned.toLong(), locale), Modifier.weight(1f))
                        Counter(stringResource(R.string.scanner_responsive), Num.grouped(state.responsive.toLong(), locale), Modifier.weight(1f))
                        Counter(
                            stringResource(R.string.scanner_best),
                            if (best >= 0) formatDelay(context, best, locale) else "—",
                            Modifier.weight(1f),
                            valueColor = if (best >= 0) c.delayColor(best) else c.muted,
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    if (state.running) {
                        TonalButton(stringResource(R.string.scanner_stop), actions.onStop, Modifier.fillMaxWidth(), icon = ZeroIcons.Close)
                    } else {
                        PrimaryButton(
                            stringResource(if (state.scanned > 0) R.string.scanner_again else R.string.scanner_start),
                            actions.onStart,
                            Modifier.fillMaxWidth(),
                            icon = ZeroIcons.Radar,
                        )
                    }
                    state.error?.let { err ->
                        Spacer(Modifier.height(12.dp))
                        ZeroCard(Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.scanner_error_title), style = MaterialTheme.typography.titleSmall, color = c.err)
                            Text(err, style = MaterialTheme.typography.bodySmall, color = c.muted)
                        }
                    }
                }
            }
            if (sorted.isNotEmpty()) {
                item(key = "results_title", contentType = "section") {
                    Row(
                        Modifier.fillMaxWidth().padding(start = 24.dp, end = 12.dp, top = 24.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(stringResource(R.string.scanner_results), style = MaterialTheme.typography.titleMedium, color = c.text, modifier = Modifier.weight(1f))
                        TonalButton(
                            stringResource(R.string.scanner_copy_best, Num.int(COPY_BEST, locale)),
                            { actions.onCopyAll(sorted.take(COPY_BEST)) },
                            icon = ZeroIcons.Copy,
                            container = androidx.compose.ui.graphics.Color.Transparent,
                            tint = c.accent,
                        )
                    }
                }
                itemsIndexed(sorted, key = { _, r -> "${r.ip}:${r.port}" }, contentType = { _, _ -> "result" }) { i, r ->
                    ResultRow(i + 1, r, actions.onCopy, Modifier.animateItem(fadeInSpec = ZeroMotion.quick(), placementSpec = ZeroMotion.quickOffset(), fadeOutSpec = ZeroMotion.quick()))
                }
            } else if (!state.running && state.scanned == 0) {
                item(key = "how", contentType = "how") {
                    ZeroCard(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 16.dp)) {
                        Text(stringResource(R.string.scanner_how_title), style = MaterialTheme.typography.titleSmall, color = c.text)
                        Spacer(Modifier.height(4.dp))
                        Text(stringResource(R.string.scanner_how_body), style = MaterialTheme.typography.bodyMedium, color = c.muted)
                    }
                }
            } else if (!state.running) {
                item(key = "none", contentType = "none") {
                    Text(
                        stringResource(R.string.scanner_none_found),
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.muted,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(32.dp),
                    )
                }
            }
        }
        ScreenTopBar(stringResource(R.string.tab_scanner), scrolled, haze)
    }
}

@Composable
private fun Counter(label: String, value: String, modifier: Modifier, valueColor: androidx.compose.ui.graphics.Color = ZeroTheme.colors.text) {
    val c = ZeroTheme.colors
    Column(
        modifier
            .clip(RowShape)
            .background(c.surface)
            .padding(horizontal = 12.dp, vertical = 12.dp)
            .semantics(mergeDescendants = true) {},
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(value, style = MaterialTheme.typography.titleLarge, color = valueColor, maxLines = 1)
        Text(label, style = MaterialTheme.typography.labelMedium, color = c.muted, maxLines = 1, textAlign = TextAlign.Center)
    }
}

@Composable
private fun ResultRow(rank: Int, r: ScanResult, onCopy: (ScanResult) -> Unit, modifier: Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 2.dp)
            .heightIn(min = 56.dp)
            .clip(CardShape)
            .background(c.surface)
            .padding(start = 16.dp, top = 4.dp, bottom = 4.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(Num.int(rank, locale), style = MaterialTheme.typography.labelLarge, color = c.muted, modifier = Modifier.width(28.dp))
        Text(
            com.zeronet.mobile.ui.util.ltr(r.ip),
            style = MaterialTheme.typography.bodyLarge,
            color = c.text,
            modifier = Modifier.weight(1f),
            maxLines = 1,
        )
        Text(
            stringResource(R.string.scanner_port, Num.int(r.port, locale)),
            style = MaterialTheme.typography.bodySmall,
            color = c.muted,
        )
        Spacer(Modifier.width(12.dp))
        Text(formatDelay(context, r.rttMs, locale), style = MaterialTheme.typography.labelLarge, color = c.delayColor(r.rttMs))
        IconAction(ZeroIcons.Copy, stringResource(R.string.scanner_copy_ip, r.ip), onClick = { onCopy(r) }, tint = c.muted, iconSize = 18.dp)
    }
}

/** A large progress ring in the orb's language: track, filled arc, and a slow sweep while running. */
@Composable
private fun ScanRing(progress: Float, running: Boolean, modifier: Modifier, content: @Composable () -> Unit) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val animated by animateFloatAsState(progress, Motion.standard(), label = "scanProgress")
    val clock = rememberAmbientClock(running && !reduced)
    Box(
        modifier.drawWithCache {
            val w = 10.dp.toPx()
            val thin = 1.5.dp.toPx()
            val track = Stroke(w, cap = StrokeCap.Round)
            val ring = Stroke(thin)
            val sweep = Stroke(thin * 2, cap = StrokeCap.Round)
            val r = size.minDimension / 2f - w
            val topLeft = Offset(size.width / 2 - r, size.height / 2 - r)
            val arcSize = Size(r * 2, r * 2)
            val center = Offset(size.width / 2, size.height / 2)
            onDrawBehind {
                drawCircle(c.border, r + w * 1.4f, center, style = ring)
                drawCircle(c.border.copy(alpha = 0.5f), r * 0.80f, center, style = ring)
                drawArc(c.surfaceHi, 0f, 360f, false, topLeft, arcSize, style = track)
                drawArc(c.accent, -90f, 360f * animated.coerceIn(0f, 1f), false, topLeft, arcSize, style = track)
                if (running) {
                    val spin = clock.floatValue / ZeroMotion.SWEEP_PERIOD_MS * 360f
                    rotate(spin, center) {
                        drawArc(c.accentBright.copy(alpha = 0.8f), -90f, 40f, false, Offset(center.x - r * 0.8f, center.y - r * 0.8f), Size(r * 1.6f, r * 1.6f), style = sweep)
                    }
                }
            }
        },
        contentAlignment = Alignment.Center,
    ) { content() }
}
