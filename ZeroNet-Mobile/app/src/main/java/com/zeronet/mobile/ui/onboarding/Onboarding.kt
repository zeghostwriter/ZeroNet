package com.zeronet.mobile.ui.onboarding

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.LocalController
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.home.BrandMark
import com.zeronet.mobile.ui.home.rememberAmbientClock
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import kotlinx.coroutines.launch
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

const val ONBOARDING_PAGES = 3

/** First run: permission requests happen at the end, after the user knows why. */
@Composable
fun OnboardingRoute(onFinished: () -> Unit) {
    val controller = LocalController.current
    // Not saveable: a pending permission callback does not survive recreation either.
    var requesting by remember { mutableStateOf(false) }
    OnboardingScreen(
        requesting = requesting,
        onAllow = {
            requesting = true
            controller.platform.requestVpnPermission {
                controller.platform.requestNotificationPermission {
                    requesting = false
                    onFinished()
                }
            }
        },
        onLater = onFinished,
    )
}

@Composable
fun OnboardingScreen(
    onAllow: () -> Unit,
    onLater: () -> Unit,
    modifier: Modifier = Modifier,
    initialPage: Int = 0,
    requesting: Boolean = false,
) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val pager = rememberPagerState(initialPage = initialPage) { ONBOARDING_PAGES }
    val scope = rememberCoroutineScope()
    val reduced = LocalReducedMotion.current
    val last = pager.currentPage == ONBOARDING_PAGES - 1
    fun go(page: Int) {
        scope.launch { if (reduced) pager.scrollToPage(page) else pager.animateScrollToPage(page) }
    }

    Column(
        modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
            .windowInsetsPadding(WindowInsets.navigationBars),
    ) {
        // Brand on the start side, Skip on the end side (hidden on the last page).
        Row(
            Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 20.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            BrandMark(Modifier.size(22.dp))
            Spacer(Modifier.width(10.dp))
            Text(stringResource(R.string.brand_name), style = MaterialTheme.typography.titleMedium, color = c.text, modifier = Modifier.weight(1f))
            if (!last) {
                TonalButton(stringResource(R.string.onboarding_skip), { go(ONBOARDING_PAGES - 1) }, container = Color.Transparent, tint = c.muted)
            }
        }
        HorizontalPager(state = pager, modifier = Modifier.weight(1f).fillMaxWidth()) { page ->
            OnboardingPage(page)
        }
        PageDots(pager.currentPage, Modifier.align(Alignment.CenterHorizontally).clearAndSetSemantics { })
        Spacer(Modifier.height(24.dp))
        Column(
            Modifier
                .widthIn(max = 480.dp)
                .fillMaxWidth()
                .align(Alignment.CenterHorizontally)
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (last) {
                PrimaryButton(stringResource(R.string.onboarding_allow), onAllow, Modifier.fillMaxWidth(), icon = ZeroIcons.Shield, loading = requesting)
                TonalButton(stringResource(R.string.onboarding_later), onLater, Modifier.fillMaxWidth(), container = Color.Transparent, tint = c.muted, enabled = !requesting)
            } else {
                PrimaryButton(
                    stringResource(R.string.onboarding_next),
                    { go(pager.currentPage + 1) },
                    Modifier.fillMaxWidth(),
                )
                // Keeps the two layouts the same height so the dots do not jump.
                Box(
                    Modifier.fillMaxWidth().heightIn(min = 48.dp).clearAndSetSemantics { },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        stringResource(R.string.onboarding_page, Num.int(pager.currentPage + 1, locale), Num.int(ONBOARDING_PAGES, locale)),
                        style = MaterialTheme.typography.labelMedium,
                        color = c.muted,
                    )
                }
            }
        }
    }
}

@Composable
private fun OnboardingPage(page: Int) {
    val c = ZeroTheme.colors
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val art = minOf(maxWidth - 96.dp, maxHeight * 0.42f, 280.dp).coerceAtLeast(140.dp)
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .heightIn(min = maxHeight)
                .padding(horizontal = 28.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            OnboardingArt(page, Modifier.size(art))
            Spacer(Modifier.height(32.dp))
            val (title, body) = when (page) {
                0 -> R.string.onboarding_1_title to R.string.onboarding_1_body
                1 -> R.string.onboarding_2_title to R.string.onboarding_2_body
                else -> R.string.onboarding_3_title to R.string.onboarding_3_body
            }
            Text(
                stringResource(title),
                style = MaterialTheme.typography.headlineSmall,
                color = c.text,
                textAlign = TextAlign.Center,
                modifier = Modifier.widthIn(max = 420.dp).semantics { heading() },
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(body),
                style = MaterialTheme.typography.bodyLarge,
                color = c.muted,
                textAlign = TextAlign.Center,
                modifier = Modifier.widthIn(max = 420.dp),
            )
            if (page == ONBOARDING_PAGES - 1) {
                Spacer(Modifier.height(24.dp))
                Column(Modifier.widthIn(max = 420.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    PermissionRow(ZeroIcons.Shield, stringResource(R.string.onboarding_perm_vpn), stringResource(R.string.onboarding_perm_vpn_body))
                    PermissionRow(ZeroIcons.Bell, stringResource(R.string.onboarding_perm_notif), stringResource(R.string.onboarding_perm_notif_body))
                }
            }
        }
    }
}

@Composable
private fun PermissionRow(icon: ImageVector, title: String, body: String) {
    val c = ZeroTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(c.surface)
            .padding(16.dp)
            .semantics(mergeDescendants = true) { },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(40.dp).clip(CircleShape).background(c.accent.copy(alpha = 0.16f)), contentAlignment = Alignment.Center) {
            Icon(icon, null, tint = c.accent, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = c.text)
            Text(body, style = MaterialTheme.typography.bodySmall, color = c.muted)
        }
    }
}

@Composable
private fun PageDots(current: Int, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    Row(modifier.height(8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
        repeat(ONBOARDING_PAGES) { i ->
            val selected = i == current
            val width by animateDpAsState(if (selected) 24.dp else 8.dp, ZeroMotion.snappy(), label = "dotWidth")
            val color by animateColorAsState(if (selected) c.accent else c.border, ZeroMotion.snappy(), label = "dotColor")
            Box(Modifier.size(width = width, height = 8.dp).clip(CircleShape).background(color))
        }
    }
}

/**
 * The orb's rings, one idea per page: connected (a calm green orb), discovery
 * (the rings reaching out to scattered servers) and permissions (a guarded
 * core). A slow breath runs in the draw phase only, and not at all under
 * reduced motion.
 */
@Composable
fun OnboardingArt(page: Int, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val clock = rememberAmbientClock(!reduced)
    val tone = when (page) {
        0 -> c.ok
        1 -> c.accent
        else -> c.info
    }
    val icon = when (page) {
        0 -> ZeroIcons.Bolt
        1 -> ZeroIcons.Radar
        else -> ZeroIcons.Shield
    }
    Box(
        modifier.drawWithCache {
            val center = Offset(size.width / 2f, size.height / 2f)
            val outer = size.minDimension / 2f * 0.86f
            val ring0 = Stroke(3.dp.toPx())
            val ring1 = Stroke(2.dp.toPx())
            val ring2 = Stroke(1.75.dp.toPx())
            val link = Stroke(1.dp.toPx())
            val glow = Brush.radialGradient(
                0f to tone.copy(alpha = if (c.isDark) 0.28f else 0.18f),
                0.6f to tone.copy(alpha = if (c.isDark) 0.08f else 0.05f),
                1f to Color.Transparent,
                center = center,
                radius = size.minDimension / 2f,
            )
            val core = Brush.radialGradient(
                0f to c.surfaceHi,
                1f to c.surface,
                center = center - Offset(0f, outer * 0.15f),
                radius = outer * 0.62f,
            )
            // Discovery page: servers scattered around the rings; the green ones "answered".
            val dots = listOf(
                0.2f to 1.08f, 0.9f to 0.9f, 1.55f to 1.12f, 2.3f to 0.95f, 2.95f to 1.1f,
                3.6f to 0.88f, 4.25f to 1.06f, 4.9f to 0.93f, 5.6f to 1.1f,
            )
            onDrawBehind {
                val t = clock.floatValue
                val breath = if (reduced) 0.5f else 0.5f - 0.5f * cos(2f * PI.toFloat() * t / ZeroMotion.BREATH_PERIOD_MS)
                drawCircle(glow, size.minDimension / 2f, center, alpha = 0.75f + 0.25f * breath)
                drawCircle(core, outer * 0.62f, center)
                drawCircle(tone.copy(alpha = 0.55f + 0.45f * breath), outer, center, style = ring0)
                drawCircle(tone.copy(alpha = 0.40f), outer * 0.80f, center, style = ring1)
                drawCircle(tone.copy(alpha = 0.75f), outer * 0.62f, center, style = ring2)
                if (page == 1) {
                    dots.forEachIndexed { i, (a, d) ->
                        val p = Offset(center.x + cos(a) * outer * d, center.y + sin(a) * outer * d)
                        val alive = i % 3 == 0
                        if (alive) drawLine(c.ok.copy(alpha = 0.45f), center + (p - center) * 0.66f, p, link.width)
                        drawCircle(if (alive) c.ok else c.muted.copy(alpha = 0.6f), (if (alive) 5f else 3.5f) * density, p)
                    }
                }
            }
        },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = tone,
            modifier = Modifier.size(44.dp),
        )
    }
}
