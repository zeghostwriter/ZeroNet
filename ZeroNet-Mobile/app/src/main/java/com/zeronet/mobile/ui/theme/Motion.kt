package com.zeronet.mobile.ui.theme

import androidx.compose.animation.core.AnimationSpec
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * Motion tokens. Everything that moves is a spring (so it can be interrupted
 * and hands velocity on), except under reduced motion, where every transition
 * becomes a short fade and ambient animation stops.
 */
object ZeroMotion {
    /** Most UI movement: settles quickly, no visible overshoot. */
    fun <T> standard(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.9f, stiffness = Spring.StiffnessMediumLow, visibilityThreshold = visibilityThreshold)

    /** Moments that should feel alive (connect, the tab pill): a soft overshoot. */
    fun <T> expressive(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.6f, stiffness = Spring.StiffnessLow, visibilityThreshold = visibilityThreshold)

    /** Small, direct feedback (press, toggles, chips). */
    fun <T> snappy(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 0.75f, stiffness = Spring.StiffnessMedium, visibilityThreshold = visibilityThreshold)

    /** Large surfaces (sheets): critically damped, a little slower. */
    fun <T> surface(visibilityThreshold: T? = null): FiniteAnimationSpec<T> =
        spring(dampingRatio = 1f, stiffness = 380f, visibilityThreshold = visibilityThreshold)

    /** The reduced-motion replacement for all of the above. */
    fun <T> fade(): FiniteAnimationSpec<T> = tween(durationMillis = 150)

    const val BREATH_PERIOD_MS = 4200f
    const val SWEEP_PERIOD_MS = 1600f
    const val MORPH_PERIOD_MS = 5200f
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
