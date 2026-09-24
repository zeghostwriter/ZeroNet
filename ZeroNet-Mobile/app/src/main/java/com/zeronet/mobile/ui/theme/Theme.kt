package com.zeronet.mobile.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import com.zeronet.mobile.model.Palette
import com.zeronet.mobile.model.ThemeMode

val LocalZeroColors = staticCompositionLocalOf { ZeroPalettes.dark(Palette.GoldenDark) }

/** Whether blurred glass may be drawn (API 31+, not in battery saver); otherwise a tinted opaque surface. */
val LocalGlassEnabled = staticCompositionLocalOf { false }

object ZeroTheme {
    val colors: ZeroColors
        @Composable @ReadOnlyComposable get() = LocalZeroColors.current
}

val ZeroShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

/** Resolves the palette the user picked into concrete colours. */
fun resolveColors(palette: Palette, dark: Boolean, amoled: Boolean): ZeroColors {
    val base = if (dark) ZeroPalettes.dark(palette) else ZeroPalettes.light(palette)
    return if (dark && amoled) ZeroPalettes.amoled(base) else base
}

@Composable
fun ZeroTheme(
    palette: Palette = Palette.GoldenDark,
    themeMode: ThemeMode = ThemeMode.System,
    dynamicColor: Boolean = false,
    amoled: Boolean = false,
    reducedMotion: Boolean = false,
    glass: Boolean = false,
    content: @Composable () -> Unit,
) {
    val dark = when (themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
    val context = LocalContext.current
    val useDynamic = dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val colors = remember(palette, dark, amoled, useDynamic) {
        val base = resolveColors(palette, dark, amoled)
        if (useDynamic) {
            val scheme = if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            fromDynamic(base, scheme, amoled && dark)
        } else {
            base
        }
    }
    val scheme = remember(colors) { colors.toColorScheme() }
    CompositionLocalProvider(
        LocalZeroColors provides colors,
        LocalReducedMotion provides reducedMotion,
        LocalGlassEnabled provides glass,
    ) {
        MaterialTheme(colorScheme = scheme, typography = ZeroTypography, shapes = ZeroShapes, content = content)
    }
}

/** Material You: take surfaces and accent from the wallpaper, keep the semantic ok/err/warn. */
private fun fromDynamic(base: ZeroColors, s: ColorScheme, amoled: Boolean): ZeroColors {
    val d = base.copy(
        bg = s.surface,
        surface = s.surfaceContainer,
        surfaceHi = s.surfaceContainerHighest,
        border = s.outlineVariant,
        muted = s.onSurfaceVariant,
        text = s.onSurface,
        accent = s.primary,
        accentBright = lerp(s.primary, s.onSurface, 0.25f),
        accentDim = s.primaryContainer,
        accentHot = s.tertiary,
        onAccent = s.onPrimary,
    )
    return if (amoled) ZeroPalettes.amoled(d) else d
}

fun ZeroColors.toColorScheme(): ColorScheme {
    val containerHigh = lerp(surface, surfaceHi, 0.5f)
    return if (isDark) {
        darkColorScheme(
            primary = accent, onPrimary = onAccent,
            primaryContainer = accentDim, onPrimaryContainer = text,
            inversePrimary = accentDim,
            secondary = accentBright, onSecondary = onAccent,
            secondaryContainer = surfaceHi, onSecondaryContainer = text,
            tertiary = info, onTertiary = bg,
            tertiaryContainer = surfaceHi, onTertiaryContainer = text,
            background = bg, onBackground = text,
            surface = bg, onSurface = text,
            surfaceVariant = surfaceHi, onSurfaceVariant = muted,
            surfaceTint = accent,
            inverseSurface = text, inverseOnSurface = bg,
            error = err, onError = bg,
            errorContainer = errDeep, onErrorContainer = text,
            outline = border, outlineVariant = hairline,
            scrim = bg,
            surfaceBright = surfaceHi, surfaceDim = bg,
            surfaceContainer = surface, surfaceContainerHigh = containerHigh,
            surfaceContainerHighest = surfaceHi, surfaceContainerLow = lerp(bg, surface, 0.6f),
            surfaceContainerLowest = bg,
        )
    } else {
        lightColorScheme(
            primary = accent, onPrimary = onAccent,
            primaryContainer = accentDim, onPrimaryContainer = text,
            inversePrimary = accentBright,
            secondary = accentBright, onSecondary = onAccent,
            secondaryContainer = surfaceHi, onSecondaryContainer = text,
            tertiary = info, onTertiary = surface,
            tertiaryContainer = surfaceHi, onTertiaryContainer = text,
            background = bg, onBackground = text,
            surface = bg, onSurface = text,
            surfaceVariant = surfaceHi, onSurfaceVariant = muted,
            surfaceTint = accent,
            inverseSurface = text, inverseOnSurface = surface,
            error = err, onError = surface,
            errorContainer = lerp(err, surface, 0.85f), onErrorContainer = text,
            outline = border, outlineVariant = hairline,
            scrim = text,
            surfaceBright = surface, surfaceDim = surfaceHi,
            surfaceContainer = surface, surfaceContainerHigh = containerHigh,
            surfaceContainerHighest = surfaceHi, surfaceContainerLow = lerp(bg, surface, 0.6f),
            surfaceContainerLowest = surface,
        )
    }
}

/**
 * Tracking for Latin-only display labels. Persian is cursive and spacing
 * breaks its joins, so in RTL (and for Persian text generally) it is zero.
 */
@Composable
@ReadOnlyComposable
fun latinTracking(em: Double): TextUnit =
    if (LocalLayoutDirection.current == LayoutDirection.Rtl) 0.em else em.em
