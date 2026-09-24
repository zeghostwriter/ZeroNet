package com.zeronet.mobile.ui.shell

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.components.LocalOverlayHost
import com.zeronet.mobile.ui.components.LocalRootHaze
import com.zeronet.mobile.ui.components.OverlayHost
import com.zeronet.mobile.ui.components.OverlayLayer
import com.zeronet.mobile.ui.components.glass
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.rememberHazeState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

enum class Tab { Home, Servers, Scanner, Settings }

/** Transient one-line confirmations ("Copied") shown above the bottom bar. */
@Stable
class AppMessages {
    var current by mutableStateOf<Pair<Long, String>?>(null)
        private set

    fun show(text: String) {
        current = System.nanoTime() to text
    }

    fun clear() {
        current = null
    }
}

val LocalAppMessages = staticCompositionLocalOf { AppMessages() }

/** Space the floating bottom bar takes from the bottom of the screen, including the navigation bar. */
val LocalBottomBarSpace = staticCompositionLocalOf { 0.dp }

private val BarHeight = 64.dp
private val BarMargin = 12.dp

/**
 * The root of every screen: page layer (a haze source), the floating glass
 * bottom bar, the transient message pill and the sheet overlay.
 */
@Composable
fun ZeroRoot(
    showBottomBar: Boolean,
    tab: Tab,
    onTab: (Tab) -> Unit,
    messages: AppMessages = remember { AppMessages() },
    content: @Composable BoxScope.() -> Unit,
) {
    val host = remember { OverlayHost() }
    val haze = rememberHazeState()
    val c = ZeroTheme.colors
    val nav = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    val barSpace = if (showBottomBar) BarHeight + BarMargin * 2 + nav else nav
    CompositionLocalProvider(
        LocalOverlayHost provides host,
        LocalRootHaze provides haze,
        LocalAppMessages provides messages,
        LocalBottomBarSpace provides barSpace,
    ) {
        Box(Modifier.fillMaxSize().background(c.bg)) {
            Box(Modifier.fillMaxSize().hazeSource(haze), content = content)
            if (showBottomBar) {
                BottomBar(
                    tab = tab,
                    onTab = onTab,
                    haze = haze,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .windowInsetsPadding(WindowInsets.navigationBars)
                        .padding(horizontal = 20.dp, vertical = BarMargin),
                )
            }
            MessagePill(messages, Modifier.align(Alignment.BottomCenter).padding(bottom = barSpace + 8.dp))
            OverlayLayer(host)
        }
    }
}

/** Tab content with a shared-axis horizontal spring between destinations. */
@Composable
fun TabHost(tab: Tab, content: @Composable (Tab) -> Unit) {
    val holder = rememberSaveableStateHolder()
    val reduced = LocalReducedMotion.current
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    AnimatedContent(
        targetState = tab,
        transitionSpec = {
            if (reduced) {
                ContentTransform(fadeIn(tween(150)), fadeOut(tween(150)))
            } else {
                val forward = targetState.ordinal > initialState.ordinal
                val dir = (if (forward) 1 else -1) * (if (rtl) -1 else 1)
                val slide = spring<androidx.compose.ui.unit.IntOffset>(dampingRatio = 0.9f, stiffness = 500f)
                (slideInHorizontally(slide) { w -> dir * w / 5 } + fadeIn(tween(220, delayMillis = 60))) togetherWith
                    (slideOutHorizontally(slide) { w -> -dir * w / 5 } + fadeOut(tween(120)))
            }
        },
        label = "tabs",
    ) { t ->
        holder.SaveableStateProvider(t.name) { content(t) }
    }
}

@Composable
private fun BottomBar(tab: Tab, onTab: (Tab) -> Unit, haze: HazeState, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val shape = RoundedCornerShape(28.dp)
    val tabs = Tab.entries
    val index = tab.ordinal
    // Liquid pill: the leading edge races ahead, the trailing edge follows on
    // a softer spring, so the pill stretches toward the target and settles.
    val lead = remember { Animatable(index.toFloat()) }
    val trail = remember { Animatable(index.toFloat()) }
    val reduced = LocalReducedMotion.current
    LaunchedEffect(index) {
        if (reduced) {
            lead.snapTo(index.toFloat()); trail.snapTo(index.toFloat())
        } else {
            launch { lead.animateTo(index.toFloat(), spring(dampingRatio = 0.8f, stiffness = 700f)) }
            launch { trail.animateTo(index.toFloat(), spring(dampingRatio = 0.85f, stiffness = 260f)) }
        }
    }
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Row(
        modifier
            .widthIn(max = 480.dp)
            .fillMaxWidth()
            .height(BarHeight)
            .glass(haze, shape)
            .drawBehind {
                val w = size.width / tabs.size
                val a = minOf(lead.value, trail.value)
                val b = maxOf(lead.value, trail.value)
                val inset = 6.dp.toPx()
                val left = if (rtl) size.width - w * (b + 1) else w * a
                val width = w * (b - a + 1)
                drawRoundRect(
                    color = c.accent.copy(alpha = if (c.isDark) 0.16f else 0.13f),
                    topLeft = Offset(left + inset, inset),
                    size = Size(width - inset * 2, size.height - inset * 2),
                    cornerRadius = CornerRadius((size.height - inset * 2) / 2),
                )
            }
            .selectableGroup(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        tabs.forEach { t ->
            BarItem(
                icon = when (t) {
                    Tab.Home -> ZeroIcons.Home
                    Tab.Servers -> ZeroIcons.Globe
                    Tab.Scanner -> ZeroIcons.Radar
                    Tab.Settings -> ZeroIcons.Settings
                },
                label = stringResource(
                    when (t) {
                        Tab.Home -> R.string.tab_home
                        Tab.Servers -> R.string.tab_servers
                        Tab.Scanner -> R.string.tab_scanner
                        Tab.Settings -> R.string.tab_settings
                    },
                ),
                selected = t == tab,
                onClick = { onTab(t) },
            )
        }
    }
}

@Composable
private fun RowScope.BarItem(icon: ImageVector, label: String, selected: Boolean, onClick: () -> Unit) {
    val c = ZeroTheme.colors
    val fg = if (selected) c.accent else c.muted
    Column(
        Modifier
            .weight(1f)
            .fillMaxHeight()
            .clip(CircleShape)
            .selectable(
                selected = selected,
                onClick = onClick,
                role = Role.Tab,
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, null, tint = fg, modifier = Modifier.size(22.dp))
        Spacer(Modifier.height(2.dp))
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = fg,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun MessagePill(messages: AppMessages, modifier: Modifier) {
    val current = messages.current
    LaunchedEffect(current) {
        if (current != null) {
            delay(2600)
            messages.clear()
        }
    }
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    AnimatedVisibility(
        visible = current != null,
        modifier = modifier,
        enter = if (reduced) fadeIn(tween(150)) else fadeIn(tween(160)) + slideInVertically(ZeroMotion.expressive()) { it / 2 },
        exit = if (reduced) fadeOut(tween(150)) else fadeOut(tween(160)) + slideOutVertically(ZeroMotion.standard()) { it / 2 },
    ) {
        var last by remember { mutableStateOf("") }
        if (current != null) last = current.second
        Text(
            last,
            style = MaterialTheme.typography.labelLarge,
            color = c.bg,
            modifier = Modifier
                .padding(horizontal = 24.dp)
                .clip(CircleShape)
                .background(c.text)
                .padding(horizontal = 18.dp, vertical = 12.dp)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
    }
}

/**
 * The compact top bar of a scrolling page. Transparent at rest (the page
 * shows its own large title); once content scrolls under it, it turns to
 * glass and shows the title.
 */
@Composable
fun ScreenTopBar(
    title: String,
    scrolled: Boolean,
    haze: HazeState,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {},
) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val progress = remember { Animatable(if (scrolled) 1f else 0f) }
    LaunchedEffect(scrolled) {
        val target = if (scrolled) 1f else 0f
        if (reduced) progress.animateTo(target, tween(150)) else progress.animateTo(target, ZeroMotion.standard())
    }
    Box(modifier.fillMaxWidth()) {
        // The glass layer fades in as a whole; content above it stays crisp.
        Box(
            Modifier
                .matchParentSize()
                .graphicsLayer { alpha = progress.value }
                .glass(haze, RoundedCornerShape(0.dp), edge = false),
        )
        Box(
            Modifier
                .matchParentSize()
                .drawBehind {
                    drawRect(
                        c.hairline.copy(alpha = progress.value),
                        topLeft = Offset(0f, size.height - 1.dp.toPx()),
                        size = Size(size.width, 1.dp.toPx()),
                    )
                },
        )
        Row(
            Modifier
                .fillMaxWidth()
                .windowInsetsPadding(WindowInsets.statusBars)
                .heightIn(min = 56.dp)
                .padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                color = c.text,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp)
                    .graphicsLayer { alpha = progress.value; translationY = (1f - progress.value) * 6.dp.toPx() }
                    .semantics { heading() },
            )
            actions()
        }
    }
}

/** The large page title shown at the top of scrolling content. */
@Composable
fun LargeTitle(text: String, modifier: Modifier = Modifier, subtitle: String? = null) {
    val c = ZeroTheme.colors
    Column(modifier.padding(horizontal = 20.dp).padding(top = 4.dp, bottom = 12.dp)) {
        Text(text, style = MaterialTheme.typography.headlineMedium, color = c.text, modifier = Modifier.semantics { heading() })
        if (subtitle != null) {
            Spacer(Modifier.height(4.dp))
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.muted)
        }
    }
}

/** Standard content padding for a page: under the top bar, above the bottom bar. */
@Composable
fun pagePadding(top: Dp = 56.dp, horizontal: Dp = 16.dp): PaddingValues {
    val status = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    return PaddingValues(start = horizontal, end = horizontal, top = status + top, bottom = LocalBottomBarSpace.current + 24.dp)
}
