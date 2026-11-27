package com.zeronet.mobile.ui.components

import androidx.activity.compose.PredictiveBackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.dismiss
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Bottom sheets are drawn by one overlay at the root of the app instead of
 * in a separate window (as ModalBottomSheet does). That keeps them in the
 * same layer tree as the page, so their glass can blur the page behind them,
 * and it lets the sheet own its physics: a spring drag with velocity hand-off
 * and iOS-style rubber-banding past the top.
 */
@Stable
class OverlayHost {
    internal val entries = mutableStateListOf<SheetEntry>()
}

@Stable
internal class SheetEntry {
    var visible by mutableStateOf(false)
    var title by mutableStateOf("")
    var onDismiss by mutableStateOf({})
    var content by mutableStateOf<@Composable ColumnScope.() -> Unit>({})
}

val LocalOverlayHost = staticCompositionLocalOf<OverlayHost?> { null }

/**
 * Shows [content] in a bottom sheet while [visible]. Declare it anywhere; it
 * renders in the root overlay above the bottom bar. [title] is announced to
 * accessibility services as the pane title.
 */
@Composable
fun ZeroSheet(
    visible: Boolean,
    onDismiss: () -> Unit,
    title: String = "",
    content: @Composable ColumnScope.() -> Unit,
) {
    val host = LocalOverlayHost.current ?: return
    val entry = remember { SheetEntry() }
    SideEffect {
        entry.visible = visible
        entry.title = title
        entry.onDismiss = onDismiss
        entry.content = content
    }
    DisposableEffect(host, entry) {
        host.entries += entry
        onDispose { host.entries -= entry }
    }
}

/** Renders every registered sheet. Place once, above the page and the bottom bar. */
@Composable
fun OverlayLayer(host: OverlayHost) {
    host.entries.forEach { entry -> key(entry) { SheetFrame(entry) } }
}

@Composable
private fun SheetFrame(entry: SheetEntry) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val haze = LocalRootHaze.current
    val scope = rememberCoroutineScope()
    val density = LocalDensity.current

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val fullPx = with(density) { maxHeight.toPx() }
        // Offset of the sheet from its resting place, in px (0 = open).
        val offset = remember { Animatable(fullPx) }
        var sheetHeight by remember { mutableFloatStateOf(fullPx) }
        var present by remember { mutableStateOf(false) }
        val backProgress = remember { Animatable(0f) }

        LaunchedEffect(entry.visible) {
            if (entry.visible) {
                present = true
                backProgress.snapTo(0f)
                if (reduced) {
                    offset.snapTo(0f)
                } else {
                    if (offset.value <= 0f) offset.snapTo(sheetHeight)
                    offset.animateTo(0f, ZeroMotion.surface())
                }
            } else if (present) {
                if (reduced) offset.animateTo(sheetHeight, tween(ZeroMotion.ms(150))) else offset.animateTo(sheetHeight.coerceAtLeast(1f), ZeroMotion.surface())
                present = false
            }
        }
        if (!present && !entry.visible) return@BoxWithConstraints

        fun settle(velocity: Float) {
            scope.launch {
                val shouldClose = velocity > 1400f || offset.value > sheetHeight * 0.33f
                if (shouldClose) {
                    entry.onDismiss()
                } else {
                    offset.animateTo(0f, ZeroMotion.surface(), initialVelocity = velocity)
                }
            }
        }

        // Past the top the sheet moves at a decaying fraction of the finger: rubber band.
        val raw = remember { floatArrayOf(0f) }
        fun dragBy(delta: Float) {
            if (offset.value >= 0f && !offset.isRunning) raw[0] = offset.value
            raw[0] += delta
            val r = raw[0]
            val next = if (r < 0f) {
                val over = -r
                -over / (1f + over / 180f) * 0.55f
            } else {
                r
            }
            scope.launch { offset.snapTo(next) }
        }

        val nested = remember {
            object : NestedScrollConnection {
                override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                    // Content scrolling up while the sheet is dragged down: close the gap first.
                    if (available.y < 0 && offset.value > 0f && source == NestedScrollSource.UserInput) {
                        val consume = maxOf(available.y, -offset.value)
                        dragBy(consume)
                        return Offset(0f, consume)
                    }
                    return Offset.Zero
                }

                override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                    // Content is at its top and the finger keeps pulling down: move the sheet.
                    if (available.y > 0 && source == NestedScrollSource.UserInput) {
                        dragBy(available.y)
                        return Offset(0f, available.y)
                    }
                    return Offset.Zero
                }

                override suspend fun onPreFling(available: Velocity): Velocity {
                    if (offset.value != 0f) {
                        settle(available.y)
                        return available
                    }
                    return Velocity.Zero
                }
            }
        }

        PredictiveBackHandler(enabled = entry.visible) { events ->
            try {
                events.collect { e -> backProgress.snapTo(e.progress) }
                entry.onDismiss()
            } catch (e: CancellationException) {
                backProgress.animateTo(0f, ZeroMotion.snappy())
                throw e
            }
        }

        // Scrim: fades with the sheet's position.
        Box(
            Modifier
                .fillMaxSize()
                .drawBehind {
                    val shown = (1f - (offset.value / sheetHeight.coerceAtLeast(1f))).coerceIn(0f, 1f)
                    drawRect(c.bg.copy(alpha = (if (c.isDark) 0.55f else 0.35f) * shown))
                }
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClickLabel = null,
                ) { entry.onDismiss() },
        )

        val maxSheet = maxHeight
        val sheetShape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
        val closeLabel = stringResource(R.string.action_close)
        Column(
            Modifier
                .align(Alignment.BottomCenter)
                .widthIn(max = 640.dp)
                .fillMaxWidth()
                .windowInsetsPadding(WindowInsets.statusBars)
                .padding(top = 24.dp)
                .onSizeChanged { sheetHeight = it.height.toFloat() }
                .graphicsLayer {
                    translationY = offset.value.coerceAtLeast(-120f)
                    val p = backProgress.value
                    val s = 1f - 0.06f * p
                    scaleX = s
                    scaleY = s
                    transformOrigin = TransformOrigin(0.5f, 1f)
                    translationY += p * 24.dp.toPx()
                }
                .glass(haze, sheetShape)
                .semantics {
                    paneTitle = entry.title
                    dismiss { entry.onDismiss(); true }
                }
                .pointerInput(Unit) { detectTapGestures { } }
                .nestedScroll(nested)
                .draggable(
                    state = rememberDraggableState { dragBy(it) },
                    orientation = Orientation.Vertical,
                    onDragStopped = { v -> settle(v) },
                )
                .windowInsetsPadding(WindowInsets.navigationBars)
                .imePadding(),
        ) {
            // Grabber
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(24.dp)
                    .semantics { contentDescription = closeLabel },
                contentAlignment = Alignment.Center,
            ) {
                Box(Modifier.size(width = 36.dp, height = 4.dp).clip(CircleShape).background(c.muted.copy(alpha = 0.5f)))
            }
            Column(Modifier.heightIn(max = maxSheet).padding(bottom = 12.dp)) {
                entry.content(this)
            }
        }
    }
}
