package com.zeronet.mobile.ui.theme

import androidx.compose.animation.core.AnimationSpec
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize

/**
 * Motion tokens. Everything that moves is a spring (so it can be interrupted
 * and hands velocity on), except under reduced motion, where every transition
 * becomes a short fade and ambient animation stops.
 */
object ZeroMotion {
    /**
     * Global tempo: every animation takes this fraction of its designed time.
     * Tweens scale their duration by it; springs scale their stiffness by
     * 1/SPEED², since a spring's settling time goes with 1/sqrt(stiffness).
     */
    const val SPEED = 0.85f

    /** A designed duration, at the app's tempo. */
    fun ms(designed: Int): Int = (designed * SPEED).toInt()

    /** A designed spring stiffness, at the app's tempo. */
    fun k(designed: Float): Float = designed / (SPEED * SPEED)

    /** Compose's default enter/exit spring, at the app's tempo. */
    fun <T> quick(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(stiffness = k(Spring.StiffnessMediumLow), visibilityThreshold = visibilityThreshold)

    fun quickSize(): FiniteAnimationSpec<IntSize> = quick(IntSize.VisibilityThreshold)
    fun quickOffset(): FiniteAnimationSpec<IntOffset> = quick(IntOffset.VisibilityThreshold)

    /** Most UI movement: settles quickly, no visible overshoot. */
    fun <T> standard(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.9f, stiffness = k(Spring.StiffnessMediumLow), visibilityThreshold = visibilityThreshold)

    /** Moments that should feel alive (connect, the tab pill): a soft overshoot. */
    fun <T> expressive(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.6f, stiffness = k(Spring.StiffnessLow), visibilityThreshold = visibilityThreshold)

    /** Small, direct feedback (press, toggles, chips). */
    fun <T> snappy(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.75f, stiffness = k(Spring.StiffnessMedium), visibilityThreshold = visibilityThreshold)

    /** Large surfaces (sheets): critically damped, a little slower. */
    fun <T> surface(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 1f, stiffness = k(380f), visibilityThreshold = visibilityThreshold)

    /** The reduced-motion replacement for all of the above. */
    fun <T> fade(): FiniteAnimationSpec<T> = tween(durationMillis = ms(150))

    const val BREATH_PERIOD_MS = 4200f * SPEED
    const val SWEEP_PERIOD_MS = 1600f * SPEED
    const val MORPH_PERIOD_MS = 5200f * SPEED
}

/** True when the user or the system asked for less motion. */
val LocalReducedMotion = staticCompositionLocalOf { false }

/** Picks the spring, or a 150 ms fade when motion is reduced. */
object Motion {
    @Composable
    @ReadOnlyComposable
    fun <T> standard(): FiniteAnimationSpec<T> = if (LocalReducedMotion.current) ZeroMotion.fade() else ZeroMotion.standard()

    @Composable
    @ReadOnlyComposable
    fun <T> expressive(): FiniteAnimationSpec<T> = if (LocalReducedMotion.current) ZeroMotion.fade() else ZeroMotion.expressive()

    @Composable
    @ReadOnlyComposable
    fun <T> snappy(): FiniteAnimationSpec<T> = if (LocalReducedMotion.current) ZeroMotion.fade() else ZeroMotion.snappy()

    @Composable
    @ReadOnlyComposable
    fun <T> surface(): AnimationSpec<T> = if (LocalReducedMotion.current) ZeroMotion.fade() else ZeroMotion.surface()
}
