package com.zeronet.mobile.ui.components

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.zeronet.mobile.ui.theme.LocalGlassEnabled
import com.zeronet.mobile.ui.theme.ZeroTheme
import dev.chrisbanes.haze.HazeInput
import dev.chrisbanes.haze.HazePerformanceMode
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.blur.HazeBlurStyle
import dev.chrisbanes.haze.blur.HazeColorEffect
import dev.chrisbanes.haze.blur.hazeBlur

/** The page-level haze source that the bottom bar and sheets sample. */
val LocalRootHaze = staticCompositionLocalOf<HazeState?> { null }

/**
 * Glass is used on exactly three surfaces: the floating bottom bar, bottom
 * sheets, and a top bar once content scrolls under it. Everything else is
 * opaque so text keeps AA contrast.
 *
 * Blur needs RenderEffect (API 31+) and costs GPU time, so below 31 and in
 * battery saver the surface is a tinted, nearly opaque fill instead.
 */
@Composable
fun Modifier.glass(state: HazeState?, shape: Shape, edge: Boolean = true): Modifier {
    val colors = ZeroTheme.colors
    val enabled = LocalGlassEnabled.current && state != null
    val style = remember(colors) {
        HazeBlurStyle {
            blurRadius(28.dp)
            noiseFactor(0.06f)
            backgroundColor(colors.bg)
            colorEffects(listOf(HazeColorEffect.tint(colors.glassTint)))
        }
    }
    val edgeBrush = remember(colors) {
        Brush.verticalGradient(0f to colors.glassEdge, 0.5f to colors.glassEdge.copy(alpha = colors.glassEdge.alpha * 0.25f), 1f to Color.Transparent)
    }
    var m = this.clip(shape)
    m = if (enabled) {
        m.hazeBlur(input = HazeInput.Sources(state), style = style, performanceMode = HazePerformanceMode.Adaptive)
    } else {
        m.background(colors.glassFallback)
    }
    return if (edge) m.border(1.dp, edgeBrush, shape) else m
}

/** Whether blur may run right now: API 31+ and battery saver off (tracked live). */
@Composable
fun rememberGlassAllowed(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
    val context = LocalContext.current
    val power = remember { context.getSystemService(PowerManager::class.java) }
    var saver by remember { mutableStateOf(power?.isPowerSaveMode == true) }
    DisposableEffect(power) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                saver = power?.isPowerSaveMode == true
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        onDispose { runCatching { context.unregisterReceiver(receiver) } }
    }
    return !saver
}
