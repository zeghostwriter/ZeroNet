package com.zeronet.mobile.ui.home

import androidx.compose.runtime.Composable
import androidx.compose.runtime.FloatState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.withFrameNanos
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle

/** The connect button's visual state (TUI `OrbState`). */
enum class OrbPhase { Idle, Busy, Connected, Failed }

/** Ambient animation frame interval: ~30 fps. */
private const val AMBIENT_FRAME_MS = 33f

/**
 * A clock in milliseconds that advances only while [running] and the screen is
 * at least RESUMED. It is read exclusively inside draw lambdas, so ticking it
 * invalidates drawing, never composition.
 *
 * It publishes at most ~30 times a second. The ambient motion it drives is
 * slow (breathing, a spinner), and every tick also forces the blurred bottom
 * bar to re-sample the page, so running it at the display's 90/120 Hz cost
 * GPU time and battery for no visible difference.
 */
@Composable
fun rememberAmbientClock(running: Boolean): FloatState {
    val time = remember { mutableFloatStateOf(0f) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(running, lifecycle) {
        if (!running) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            var last = -1L
            var pending = 0f
            while (true) {
                withFrameNanos { now ->
                    if (last >= 0) pending += (now - last) / 1_000_000f
                    last = now
                    if (pending >= AMBIENT_FRAME_MS) {
                        time.floatValue += pending
                        pending = 0f
                    }
                }
            }
        }
    }
    return time
}
