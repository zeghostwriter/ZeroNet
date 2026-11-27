package com.zeronet.mobile.ui.home

import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshots.Snapshot
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.TextUnitType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zeronet.mobile.ui.effects.ProtocolBannerFx
import com.zeronet.mobile.ui.theme.LocalReducedMotion

/** The reference size the text is measured at before it is scaled to fit the width. */
private const val MEASURE_SP = 40f
private const val MAX_SP = 52f
private const val MIN_SP = 15f

/**
 * The line that appears above the globe when a connection comes up: the
 * protocol and its carrier in big retro-neon lettering, like `VLESS + REALITY`.
 *
 * Each protocol has one colour and its own typeface ([ProtocolBannerFx.look]).
 * Back to front: a wide glow in that colour; two ghost copies pushed apart (the
 * echo that breathes and glitches); the letters, in a hotter shade of the same
 * colour; a glint that sweeps across now and then; thin scanlines over all of
 * it. The text first churns like cipher text and settles left to right. With
 * reduced motion it is the finished picture, still.
 *
 * Cost: the glow (blurred text) and the scanlines never change once the text
 * has settled, so they are drawn once into their own cached layers and only
 * composited afterwards. Per frame the banner redraws just the echo, letters
 * and glint from text layouts measured once per distinct text; the fade and the
 * landing scale are layer properties, so they redraw nothing. Nothing here
 * recomposes on a clock tick: the clock is only read in draw and layer blocks.
 *
 * It says nothing about being connected: the globe and the card below already do.
 */
@Composable
fun ProtocolBanner(
    text: String,
    look: ProtocolBannerFx.Look,
    runs: List<ProtocolBannerFx.Run>,
    modifier: Modifier = Modifier,
) {
    val reduced = LocalReducedMotion.current
    val clock = rememberAmbientClock(!reduced)
    // The clock only ticks while visible; this banner's own time starts at zero when it is created.
    // Read without observing, so composition does not rerun on every tick.
    val startedAt = remember(text) { Snapshot.withoutReadObservation { clock.floatValue.toLong() } }
    val elapsedNow = { if (reduced) Long.MAX_VALUE / 4 else (clock.floatValue.toLong() - startedAt).coerceAtLeast(0) }
    val measurer = rememberTextMeasurer(cacheSize = 8)
    val seed = remember(text) { ProtocolBannerFx.seed(text) }
    val density = LocalDensity.current
    val bold = remember(look) {
        FontFamily(Typeface.create(look.font, if (look.italic) Typeface.BOLD_ITALIC else Typeface.BOLD))
    }
    val regular = remember(look) {
        FontFamily(Typeface.create(look.font, if (look.italic) Typeface.ITALIC else Typeface.NORMAL))
    }
    val color = Color(look.color)
    // The letters are the colour with a touch of white, so they read as the hot core of the glow.
    val hot = remember(look) { lerp(color, Color.White, 0.16f) }
    // The text as it is right now. A derived state: it only changes when the characters do (about
    // twenty times while churning, never once settled), so the banner recomposes that rarely.
    val shown by remember(text, reduced) {
        derivedStateOf { if (reduced) text else ProtocolBannerFx.scramble(text, elapsedNow(), seed) }
    }
    val hasInk = remember(runs) { runs.any { it.ink } }

    BoxWithConstraints(modifier.fillMaxWidth().clearAndSetSemantics { contentDescription = text }) {
        val widthPx = with(density) { maxWidth.toPx() }
        val base = remember(look) {
            TextStyle(fontFamily = bold, letterSpacing = look.tracking.sp, fontSize = MEASURE_SP.sp)
        }
        // The line with every run styled: `colorOf` picks each run's colour.
        fun styled(source: String, colorOf: (ProtocolBannerFx.Run) -> Color): AnnotatedString = buildAnnotatedString {
            append(source)
            runs.forEach { run ->
                val end = run.end.coerceAtMost(source.length)
                if (run.start < end) {
                    addStyle(SpanStyle(color = colorOf(run), fontFamily = if (run.bold) bold else regular), run.start, end)
                }
            }
        }
        // Fit the whole line to the width: text grows in a straight line with its size.
        val style = remember(text, runs, base, widthPx) {
            val unit = measurer.measure(styled(text) { Color.Transparent }, base).size.width.coerceAtLeast(1)
            val fitted = (MEASURE_SP * (widthPx * 0.94f) / unit).coerceIn(MIN_SP, MAX_SP)
            base.copy(fontSize = TextUnit(fitted, TextUnitType.Sp))
        }
        // Every layout for the current text, measured once per distinct text.
        val layouts = remember(shown, runs, style, color, hot) {
            val glowText = styled(shown) { Color.Transparent }
            Layouts(
                core = measurer.measure(styled(shown) { run -> run.color?.let { Color(it) } ?: hot }, style),
                glowWide = measurer.measure(glowText, style.copy(shadow = Shadow(color, Offset.Zero, 30f))),
                glowTight = measurer.measure(glowText, style.copy(shadow = Shadow(hot, Offset.Zero, 12f))),
                // Only the black letters, in the protocol's colour: drawn as an outline around them.
                outline = if (hasInk) measurer.measure(styled(shown) { run -> if (run.ink) color else Color.Transparent }, style) else null,
            )
        }
        val textW = layouts.core.size.width.toFloat()
        val textH = layouts.core.size.height.toFloat()

        // The fade-in and the landing scale are layer properties: no redraw, just a new transform.
        Box(
            Modifier.fillMaxWidth().height(64.dp).graphicsLayer {
                val e = elapsedNow()
                alpha = ProtocolBannerFx.alpha(e)
                val land = ProtocolBannerFx.scale(e)
                scaleX = land
                scaleY = land
            },
        ) {
            // Glow: the same letters, blurred. Static, so it is drawn once into a cached layer.
            Canvas(Modifier.fillMaxWidth().height(64.dp).graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }) {
                val origin = Offset((size.width - textW) / 2f, (size.height - textH) / 2f)
                drawText(layouts.glowWide, topLeft = origin, alpha = 0.9f)
                drawText(layouts.glowTight, topLeft = origin, alpha = 0.7f)
            }
            // The moving part: echo, letters, glint. Three or four plain text draws per frame.
            Canvas(Modifier.fillMaxWidth().height(64.dp)) {
                val elapsed = elapsedNow()
                val origin = Offset((size.width - textW) / 2f, (size.height - textH) / 2f)
                val split = if (reduced) 0.3f else ProtocolBannerFx.split(elapsed, seed)
                val shift = split * 5.dp.toPx()
                // The echo: two dimmer copies either side, added so the overlap brightens.
                drawText(layouts.core, color = color, topLeft = origin - Offset(shift, 0f), alpha = 0.5f, blendMode = BlendMode.Plus)
                drawText(layouts.core, color = color, topLeft = origin + Offset(shift, 0f), alpha = 0.5f, blendMode = BlendMode.Plus)
                drawText(layouts.core, color = hot, topLeft = origin)
                // The black letters would vanish on a dark screen: a thin outline in the colour keeps them there.
                layouts.outline?.let { drawText(it, topLeft = origin, drawStyle = Stroke(width = 1.4.dp.toPx())) }
                val glintAt = if (reduced) 2f else ProtocolBannerFx.glint(elapsed)
                if (glintAt in -0.3f..1.3f) {
                    val gx = origin.x + textW * glintAt
                    drawText(
                        layouts.core,
                        brush = Brush.linearGradient(
                            colorStops = arrayOf(0f to Color.Transparent, 0.5f to Color.White, 1f to Color.Transparent),
                            start = Offset(gx - textW * 0.12f, 0f),
                            end = Offset(gx + textW * 0.12f, 0f),
                        ),
                        topLeft = origin,
                        alpha = 0.85f,
                    )
                }
            }
            // Scanlines: thin dark bars every few pixels, like an old monitor. Static, cached.
            Canvas(Modifier.fillMaxWidth().height(64.dp).graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }) {
                val originX = (size.width - textW) / 2f
                val originY = (size.height - textH) / 2f
                val pitch = 4.dp.toPx()
                val pad = 8.dp.toPx()
                var y = originY
                while (y < originY + textH) {
                    drawLine(Color.Black, Offset(originX - pad, y), Offset(originX + textW + pad, y), strokeWidth = 0.8f.dp.toPx(), alpha = 0.22f)
                    y += pitch
                }
            }
        }
    }
}

/** The text layouts for one distinct banner text: letters, the two glows, and the outline of the ink letters. */
private class Layouts(
    val core: TextLayoutResult,
    val glowWide: TextLayoutResult,
    val glowTight: TextLayoutResult,
    val outline: TextLayoutResult?,
)
