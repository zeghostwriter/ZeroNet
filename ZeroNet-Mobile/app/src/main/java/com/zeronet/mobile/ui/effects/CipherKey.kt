package com.zeronet.mobile.ui.effects

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zeronet.mobile.ui.effects.KeyFx.Kind
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlinx.coroutines.isActive

/** Milliseconds per effect tick, the terminal app's frame time. */
private const val TICK_MS = 60L

/**
 * A row of cipher text that decrypts into [target]. While [target] is null it
 * churns; once known, a bright front sweeps across it left to right and leaves
 * the real characters behind. [placeholder] sets the shape of the churn.
 * Under reduced motion it shows the settled row, or the placeholder, still.
 */
@Composable
fun CipherKey(
    target: String?,
    placeholder: String,
    description: String,
    modifier: Modifier = Modifier,
    seed: ULong = 0x5A17uL,
) {
    val reduced = LocalReducedMotion.current
    val template = target ?: placeholder
    val count = template.count { it != ' ' }

    // The clock. `revealStart` is the tick the key became known.
    var tick by remember { mutableLongStateOf(0L) }
    var revealStart by remember { mutableLongStateOf(-1L) }
    LaunchedEffect(target, reduced) {
        if (reduced) return@LaunchedEffect
        val begin = withFrameNanos { it }
        val base = tick
        if (target != null && revealStart < 0) revealStart = base
        if (target == null) revealStart = -1
        while (isActive) {
            val frame = withFrameNanos { it }
            val now = base + (frame - begin) / 1_000_000L / TICK_MS
            if (now != tick) tick = now
            if (target != null && now - revealStart >= KeyFx.revealDuration(count)) break
        }
    }

    val c = ZeroTheme.colors
    val measurer = rememberTextMeasurer()
    val density = LocalDensity.current
    BoxWithConstraints(modifier.fillMaxWidth()) {
    // A monospace glyph is about 0.6 em wide: shrink the type until the whole row fits.
    val fitted = with(density) { (constraints.maxWidth / (template.length * 0.6f)).toSp() }
    val style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = if (fitted.value < 17f) fitted else 17.sp)
    val cell = remember(measurer, density) {
        measurer.measure("0", style).size.width.toFloat()
    }
    val lineHeight = remember(measurer) { measurer.measure("0", style).size.height.toFloat() }

    val cells = when {
        reduced -> KeyFx.frame(template, 0, if (target != null) count else null, seed)
        target != null && revealStart >= 0 ->
            KeyFx.frame(template, tick, KeyFx.settled(tick - revealStart, count), seed)
        else -> KeyFx.frame(template, tick, null, seed)
    }

    Canvas(
        Modifier
            .fillMaxWidth()
            .height(with(density) { (lineHeight * 1.6f).toDp() })
            .clearAndSetSemantics { contentDescription = description },
    ) {
        val total = template.length * cell
        var x = (size.width - total) / 2f
        val y = (size.height - lineHeight) / 2f
        for (item in cells) {
            val color: Color = when (item.kind) {
                Kind.Gap -> Color.Transparent
                Kind.Locked -> c.text
                Kind.Front -> c.accentHot
                Kind.Churn -> c.accentDim
                Kind.Wide -> c.warn
            }
            if (item.kind != Kind.Gap) {
                val layout = measurer.measure(item.ch.toString(), style.copy(color = color))
                // A wide character is centred over its two columns.
                val slack = (item.width * cell - layout.size.width) / 2f
                drawText(layout, topLeft = Offset(x + slack, y))
            }
            x += item.width * cell
        }
    }
    }
}
