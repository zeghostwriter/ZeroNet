package com.zeronet.mobile.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import com.zeronet.mobile.model.Palette

/**
 * The app's semantic colours. The roles are the same ones the terminal app
 * (`zeronet-tui/src/theme.rs`) is built from, so the phone and the terminal
 * read as one product; Material 3's [androidx.compose.material3.ColorScheme]
 * is derived from these in [ZeroTheme].
 */
@Immutable
data class ZeroColors(
    val isDark: Boolean,
    val bg: Color,
    val surface: Color,
    val surfaceHi: Color,
    val border: Color,
    val muted: Color,
    val text: Color,
    val accent: Color,
    val accentBright: Color,
    val accentDim: Color,
    val accentHot: Color,
    /** Text/icons drawn on a filled [accent] surface. */
    val onAccent: Color,
    val ok: Color,
    val warn: Color,
    val err: Color,
    val info: Color,
) {
    /** Bright end of the connected breath (TUI `ok_bright`). */
    val okBright: Color get() = lerp(ok, text, 0.3f)

    /** Dim end of the connected breath, also the innermost connected ring (TUI `ok_deep`). */
    val okDeep: Color get() = lerp(ok, bg, 0.55f)

    /** Error colour sunk into the background, for broken-ring shading (TUI `err_deep`). */
    val errDeep: Color get() = lerp(err, bg, 0.5f)

    /** The glass tint: the page colour, translucent. */
    val glassTint: Color get() = bg.copy(alpha = if (isDark) 0.62f else 0.70f)

    /** The opaque fallback when blur is unavailable (API < 31, battery saver). */
    val glassFallback: Color get() = lerp(surface, surfaceHi, 0.35f)

    /** The 1 dp inner highlight on glass edges. */
    val glassEdge: Color get() = if (isDark) Color.White.copy(alpha = 0.10f) else Color.White.copy(alpha = 0.75f)

    /** A hairline divider, one step quieter than [border]. */
    val hairline: Color get() = lerp(border, surface, 0.45f)

    /** Colour for a real-delay value: green when quick, amber when usable, red when slow. */
    fun delayColor(ms: Int): Color = when {
        ms < 0 -> muted
        ms < 300 -> ok
        ms < 800 -> warn
        else -> err
    }
}

private fun rgb(r: Int, g: Int, b: Int) = Color(r, g, b)

/** The TUI palettes, verbatim (dark), plus light variants derived for AA contrast on white. */
object ZeroPalettes {

    fun dark(p: Palette): ZeroColors = when (p) {
        Palette.GoldenDark -> ZeroColors(
            isDark = true,
            bg = rgb(13, 15, 18), surface = rgb(22, 25, 32), surfaceHi = rgb(36, 41, 52),
            border = rgb(45, 52, 66), muted = rgb(128, 141, 163), text = rgb(226, 232, 240),
            accent = rgb(245, 158, 11), accentBright = rgb(251, 191, 36), accentDim = rgb(146, 92, 12),
            accentHot = rgb(249, 115, 22), onAccent = rgb(20, 14, 4),
            ok = rgb(16, 185, 129), warn = rgb(249, 115, 22), err = rgb(239, 68, 68), info = rgb(56, 152, 233),
        )
        Palette.Nightshade -> ZeroColors(
            isDark = true,
            bg = rgb(17, 15, 26), surface = rgb(27, 24, 40), surfaceHi = rgb(42, 37, 62),
            border = rgb(56, 50, 84), muted = rgb(146, 140, 176), text = rgb(236, 233, 248),
            accent = rgb(139, 110, 255), accentBright = rgb(176, 156, 255), accentDim = rgb(84, 62, 176),
            accentHot = rgb(214, 92, 255), onAccent = rgb(255, 255, 255),
            ok = rgb(29, 196, 137), warn = rgb(240, 164, 64), err = rgb(237, 85, 101), info = rgb(96, 170, 255),
        )
        Palette.Arctic -> ZeroColors(
            isDark = true,
            bg = rgb(12, 17, 25), surface = rgb(19, 28, 40), surfaceHi = rgb(30, 44, 62),
            border = rgb(42, 60, 84), muted = rgb(124, 148, 176), text = rgb(226, 236, 246),
            accent = rgb(56, 152, 233), accentBright = rgb(125, 196, 255), accentDim = rgb(30, 88, 146),
            accentHot = rgb(45, 212, 191), onAccent = rgb(4, 16, 30),
            ok = rgb(34, 197, 94), warn = rgb(245, 158, 11), err = rgb(239, 68, 68), info = rgb(45, 212, 191),
        )
        Palette.Sakura -> ZeroColors(
            isDark = true,
            bg = rgb(21, 15, 19), surface = rgb(32, 23, 29), surfaceHi = rgb(48, 34, 44),
            border = rgb(70, 48, 62), muted = rgb(172, 142, 160), text = rgb(250, 236, 244),
            accent = rgb(244, 114, 182), accentBright = rgb(251, 168, 212), accentDim = rgb(150, 58, 108),
            accentHot = rgb(255, 88, 140), onAccent = rgb(36, 8, 22),
            ok = rgb(52, 211, 153), warn = rgb(251, 146, 60), err = rgb(248, 80, 80), info = rgb(129, 140, 248),
        )
        // Paper is the TUI's light palette; its dark form is a warm sepia night.
        Palette.Paper -> ZeroColors(
            isDark = true,
            bg = rgb(24, 22, 19), surface = rgb(34, 31, 27), surfaceHi = rgb(50, 46, 40),
            border = rgb(68, 62, 54), muted = rgb(166, 156, 142), text = rgb(240, 234, 222),
            accent = rgb(226, 150, 58), accentBright = rgb(240, 180, 96), accentDim = rgb(128, 84, 30),
            accentHot = rgb(232, 110, 40), onAccent = rgb(28, 18, 6),
            ok = rgb(46, 184, 128), warn = rgb(232, 128, 48), err = rgb(236, 86, 76), info = rgb(96, 156, 226),
        )
        Palette.Contrast -> ZeroColors(
            isDark = true,
            bg = rgb(0, 0, 0), surface = rgb(10, 10, 10), surfaceHi = rgb(44, 44, 44),
            border = rgb(128, 128, 128), muted = rgb(190, 190, 190), text = rgb(255, 255, 255),
            accent = rgb(255, 214, 0), accentBright = rgb(255, 240, 110), accentDim = rgb(150, 126, 0),
            accentHot = rgb(255, 160, 0), onAccent = rgb(0, 0, 0),
            ok = rgb(0, 230, 118), warn = rgb(255, 160, 0), err = rgb(255, 82, 82), info = rgb(64, 196, 255),
        )
    }

    fun light(p: Palette): ZeroColors = when (p) {
        Palette.GoldenDark -> ZeroColors(
            isDark = false,
            bg = rgb(247, 245, 241), surface = rgb(255, 255, 255), surfaceHi = rgb(238, 234, 226),
            border = rgb(214, 208, 198), muted = rgb(94, 98, 108), text = rgb(24, 26, 30),
            accent = rgb(180, 83, 9), accentBright = rgb(217, 119, 6), accentDim = rgb(246, 222, 180),
            accentHot = rgb(194, 65, 12), onAccent = rgb(255, 255, 255),
            ok = rgb(4, 120, 87), warn = rgb(194, 65, 12), err = rgb(185, 28, 28), info = rgb(29, 78, 216),
        )
        Palette.Nightshade -> ZeroColors(
            isDark = false,
            bg = rgb(246, 244, 252), surface = rgb(255, 255, 255), surfaceHi = rgb(234, 230, 248),
            border = rgb(210, 204, 232), muted = rgb(96, 92, 118), text = rgb(26, 22, 40),
            accent = rgb(98, 70, 220), accentBright = rgb(124, 96, 240), accentDim = rgb(222, 214, 255),
            accentHot = rgb(164, 52, 206), onAccent = rgb(255, 255, 255),
            ok = rgb(4, 120, 87), warn = rgb(180, 83, 9), err = rgb(190, 30, 60), info = rgb(37, 99, 235),
        )
        Palette.Arctic -> ZeroColors(
            isDark = false,
            bg = rgb(243, 247, 251), surface = rgb(255, 255, 255), surfaceHi = rgb(228, 237, 246),
            border = rgb(200, 214, 230), muted = rgb(86, 100, 118), text = rgb(16, 24, 36),
            accent = rgb(21, 101, 176), accentBright = rgb(37, 128, 214), accentDim = rgb(208, 228, 248),
            accentHot = rgb(13, 128, 116), onAccent = rgb(255, 255, 255),
            ok = rgb(21, 128, 61), warn = rgb(180, 83, 9), err = rgb(185, 28, 28), info = rgb(13, 118, 110),
        )
        Palette.Sakura -> ZeroColors(
            isDark = false,
            bg = rgb(252, 244, 248), surface = rgb(255, 255, 255), surfaceHi = rgb(248, 230, 240),
            border = rgb(232, 204, 220), muted = rgb(112, 88, 102), text = rgb(38, 20, 30),
            accent = rgb(190, 24, 93), accentBright = rgb(219, 39, 119), accentDim = rgb(252, 218, 234),
            accentHot = rgb(200, 30, 70), onAccent = rgb(255, 255, 255),
            ok = rgb(4, 120, 87), warn = rgb(194, 65, 12), err = rgb(185, 28, 28), info = rgb(67, 56, 202),
        )
        Palette.Paper -> ZeroColors(
            isDark = false,
            bg = rgb(244, 241, 234), surface = rgb(252, 250, 246), surfaceHi = rgb(230, 225, 214),
            border = rgb(200, 193, 180), muted = rgb(106, 98, 88), text = rgb(32, 30, 28),
            accent = rgb(166, 90, 6), accentBright = rgb(206, 120, 14), accentDim = rgb(236, 214, 180),
            accentHot = rgb(190, 68, 10), onAccent = rgb(255, 255, 255),
            ok = rgb(4, 122, 82), warn = rgb(184, 80, 10), err = rgb(186, 36, 36), info = rgb(28, 96, 176),
        )
        Palette.Contrast -> ZeroColors(
            isDark = false,
            bg = rgb(255, 255, 255), surface = rgb(255, 255, 255), surfaceHi = rgb(232, 232, 232),
            border = rgb(64, 64, 64), muted = rgb(56, 56, 56), text = rgb(0, 0, 0),
            accent = rgb(0, 0, 0), accentBright = rgb(40, 40, 40), accentDim = rgb(220, 220, 220),
            accentHot = rgb(120, 60, 0), onAccent = rgb(255, 255, 255),
            ok = rgb(0, 102, 51), warn = rgb(150, 60, 0), err = rgb(176, 0, 0), info = rgb(0, 70, 170),
        )
    }

    /** Pure-black surfaces for OLED screens; keeps each palette's accents. */
    fun amoled(c: ZeroColors): ZeroColors = c.copy(
        bg = Color.Black,
        surface = lerp(Color.Black, c.surface, 0.55f),
        surfaceHi = lerp(Color.Black, c.surfaceHi, 0.8f),
    )

    /** The swatch colours shown in Settings → Appearance, independent of light/dark. */
    fun swatch(p: Palette): Pair<Color, Color> {
        val d = dark(p)
        return when (p) {
            Palette.Paper -> light(p).bg to light(p).accent
            else -> d.bg to d.accent
        }
    }
}
