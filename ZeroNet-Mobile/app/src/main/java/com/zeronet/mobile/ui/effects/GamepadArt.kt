package com.zeronet.mobile.ui.effects

import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathOperation
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.lerp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * The colours of the gaming switch-on scene. It is a night scene whatever the
 * app's theme is, so these are fixed: the cyan and magenta are the same neon
 * pair as the dark gaming theme.
 */
internal object Neon {
    val Cyan = Color(0xFF22E3FF)
    val Magenta = Color(0xFFFF2BD6)
    val Night = Color(0xFF05060D)
}

private val SHELL_TOP = Color(0xFF2D3252)
private val SHELL_BOTTOM = Color(0xFF0B0D1B)
private val SHOULDER = Color(0xFF1A1D33)
private val WELL = Color(0xFF07080F)
private val KEY_TOP = Color(0xFF454B6B)
private val KEY_BOTTOM = Color(0xFF1B1E33)

private val GREEN = Color(0xFF3DFF9A)
private val RED = Color(0xFFFF5A6E)
private val BLUE = Color(0xFF4DA3FF)
private val YELLOW = Color(0xFFFFD84D)

/**
 * The controller's fixed parts: the shapes and gradients that never change
 * from one frame to the next, built once and reused by [drawGamepad].
 *
 * Everything is laid out in a [W] by [H] design box (x to the right, y down)
 * and scaled to the canvas when drawn, so the numbers below are positions in
 * that box, not pixels.
 */
internal class GamepadArt {
    /**
     * The shell seen from the front: a wide middle, two shoulders and two
     * grips hanging below it. Drawn clockwise from the middle of the top
     * edge; the left half is the right half mirrored around x = 160.
     */
    val body: Path = Path().apply {
        moveTo(160f, 44f)
        lineTo(206f, 44f)
        cubicTo(232f, 44f, 258f, 46f, 274f, 56f)
        cubicTo(292f, 68f, 300f, 98f, 306f, 134f)
        cubicTo(311f, 164f, 308f, 200f, 286f, 204f)
        cubicTo(266f, 208f, 256f, 192f, 246f, 174f)
        cubicTo(238f, 160f, 224f, 150f, 202f, 150f)
        lineTo(118f, 150f)
        cubicTo(96f, 150f, 82f, 160f, 74f, 174f)
        cubicTo(64f, 192f, 54f, 208f, 34f, 204f)
        cubicTo(12f, 200f, 9f, 164f, 14f, 134f)
        cubicTo(20f, 98f, 28f, 68f, 46f, 56f)
        cubicTo(62f, 46f, 88f, 44f, 114f, 44f)
        close()
    }

    /** The d-pad's cross, as one outline. */
    val dpad: Path = Path.combine(
        PathOperation.Union,
        Path().apply { addRoundRect(RoundRect(Rect(DPAD.x - 16f, DPAD.y - 5.5f, DPAD.x + 16f, DPAD.y + 5.5f), CornerRadius(3f))) },
        Path().apply { addRoundRect(RoundRect(Rect(DPAD.x - 5.5f, DPAD.y - 16f, DPAD.x + 5.5f, DPAD.y + 16f), CornerRadius(3f))) },
    )

    val shell = Brush.verticalGradient(listOf(SHELL_TOP, SHELL_BOTTOM), startY = 44f, endY = 206f)
    val sheen = Brush.verticalGradient(listOf(Color.White.copy(alpha = 0.18f), Color.Transparent), startY = 44f, endY = 96f)
    val shade = Brush.verticalGradient(listOf(Color.Transparent, Color.Black.copy(alpha = 0.40f)), startY = 146f, endY = 206f)
    val edge = Brush.horizontalGradient(listOf(Neon.Cyan, Neon.Magenta), startX = 10f, endX = 310f)
    val key = Brush.verticalGradient(listOf(KEY_TOP, KEY_BOTTOM), startY = DPAD.y - 16f, endY = DPAD.y + 16f)
    val bar = Brush.horizontalGradient(listOf(Neon.Cyan, Neon.Magenta), startX = BAR_FROM, endX = BAR_TO)

    companion object {
        const val W = 320f
        const val H = 210f
        const val BAR_FROM = 138f
        const val BAR_TO = 182f
        val DPAD = Offset(84f, 96f)
        val FACE = Offset(236f, 96f)
        val LEFT_STICK = Offset(122f, 127f)
        val RIGHT_STICK = Offset(198f, 127f)
        val HOME = Offset(160f, 108f)

        /** Where [pad] sits in the design box: the point its press lights up from. */
        fun anchor(pad: Pad): Offset = when (pad) {
            Pad.LeftStick -> LEFT_STICK
            Pad.RightStick -> RIGHT_STICK
            Pad.DPadRight -> DPAD + Offset(10f, 0f)
            Pad.X -> FACE + Offset(-17f, 0f)
            Pad.Y -> FACE + Offset(0f, -17f)
            Pad.B -> FACE + Offset(17f, 0f)
            Pad.A -> FACE + Offset(0f, 17f)
            Pad.LeftBumper -> Offset(83f, 40f)
            Pad.RightBumper -> Offset(237f, 40f)
            Pad.LeftTrigger -> Offset(83f, 26f)
            Pad.RightTrigger -> Offset(237f, 26f)
        }

        /** The colour [pad] lights up in. */
        fun tint(pad: Pad): Color = when (pad) {
            Pad.X -> BLUE
            Pad.Y -> YELLOW
            Pad.B -> RED
            Pad.A -> GREEN
            Pad.LeftTrigger, Pad.RightTrigger -> Neon.Magenta
            else -> Neon.Cyan
        }
    }
}

/**
 * Draws the controller as it looks [ms] milliseconds into the animation,
 * filling the canvas's width. Back to front: triggers and bumpers, the shell
 * and its neon edge, the middle panel, d-pad, face buttons, sticks, and last
 * the sparks each press throws off (those may spill outside the canvas).
 *
 * The neon gets brighter as [GamepadTimeline.charge] climbs, so the controller
 * looks like it is powering up while its buttons are pressed.
 */
internal fun DrawScope.drawGamepad(art: GamepadArt, ms: Float) {
    val k = size.width / GamepadArt.W
    val charge = GamepadTimeline.charge(ms)
    val surge = GamepadTimeline.kick(ms)
    scale(k, k, pivot = Offset.Zero) {
        drawShoulders(ms)
        drawShell(art, charge, surge)
        drawMiddle(art, charge, surge)
        drawDpad(art, ms)
        for (pad in listOf(Pad.Y, Pad.X, Pad.B, Pad.A)) drawFaceButton(pad, ms, charge)
        drawStick(Pad.LeftStick, ms, turn = 1f)
        drawStick(Pad.RightStick, ms, turn = -1f)
        for (pad in Pad.entries) drawSparks(pad, ms)
    }
}

/** Triggers behind, bumpers in front of them; both sink a little when pressed and take their colour. */
private fun DrawScope.drawShoulders(ms: Float) {
    val sides = listOf(
        Triple(Pad.LeftTrigger, Pad.LeftBumper, 50f),
        Triple(Pad.RightTrigger, Pad.RightBumper, 204f),
    )
    for ((trigger, bumper, x) in sides) {
        val pull = GamepadTimeline.depth(trigger, ms)
        val triggerAt = Offset(x + 8f, 18f + 8f * pull)
        drawRoundRect(lerp(SHOULDER, Neon.Magenta, pull), triggerAt, Size(50f, 30f), CornerRadius(11f))
        drawRoundRect(Neon.Magenta.copy(alpha = 0.30f + 0.70f * pull), triggerAt, Size(50f, 30f), CornerRadius(11f), style = Stroke(1.5f))
        val tap = GamepadTimeline.depth(bumper, ms)
        val bumperAt = Offset(x, 33f + 3f * tap)
        drawRoundRect(lerp(SHOULDER, Neon.Cyan, tap), bumperAt, Size(66f, 22f), CornerRadius(9f))
        drawRoundRect(Neon.Cyan.copy(alpha = 0.35f + 0.65f * tap), bumperAt, Size(66f, 22f), CornerRadius(9f), style = Stroke(1.5f))
    }
}

/**
 * The shell: a dark body lit from above, with the grips falling into shadow,
 * and a neon outline. The glow is the same outline drawn wider and fainter
 * underneath, which costs far less than a real blur.
 */
private fun DrawScope.drawShell(art: GamepadArt, charge: Float, surge: Float) {
    drawPath(art.body, art.shell)
    clipPath(art.body) {
        drawRect(art.sheen, Offset(0f, 44f), Size(GamepadArt.W, 52f))
        drawRect(art.shade, Offset(0f, 146f), Size(GamepadArt.W, 60f))
    }
    // The faceplate's seam: the outline again, a little smaller.
    scale(0.93f, 0.88f, pivot = Offset(160f, 104f)) {
        drawPath(art.body, Color.White, alpha = 0.05f, style = Stroke(1.2f))
    }
    val power = 0.30f + 0.70f * charge
    drawPath(art.body, art.edge, alpha = 0.10f * power * (1f + surge), style = Stroke(13f + 12f * surge, join = StrokeJoin.Round))
    drawPath(art.body, art.edge, alpha = 0.24f * power, style = Stroke(6f, join = StrokeJoin.Round))
    drawPath(art.body, art.edge, alpha = 0.40f + 0.60f * charge, style = Stroke(2.2f, join = StrokeJoin.Round))
}

/** The middle: a dark panel whose light bar fills with the charge, two small keys and the home button. */
private fun DrawScope.drawMiddle(art: GamepadArt, charge: Float, surge: Float) {
    drawRoundRect(WELL, Offset(130f, 56f), Size(60f, 34f), CornerRadius(8f))
    drawRoundRect(Color.White.copy(alpha = 0.10f), Offset(130f, 56f), Size(60f, 34f), CornerRadius(8f), style = Stroke(1f))
    val y = 82f
    drawLine(Color.White.copy(alpha = 0.12f), Offset(GamepadArt.BAR_FROM, y), Offset(GamepadArt.BAR_TO, y), strokeWidth = 3f, cap = StrokeCap.Round)
    if (charge > 0.01f) {
        val to = Offset(GamepadArt.BAR_FROM + (GamepadArt.BAR_TO - GamepadArt.BAR_FROM) * charge, y)
        drawLine(art.bar, Offset(GamepadArt.BAR_FROM, y), to, strokeWidth = 8f, cap = StrokeCap.Round, alpha = 0.25f)
        drawLine(art.bar, Offset(GamepadArt.BAR_FROM, y), to, strokeWidth = 3f, cap = StrokeCap.Round)
    }
    for (x in listOf(109f, 201f)) {
        drawRoundRect(Color.White.copy(alpha = 0.30f), Offset(x, 62f), Size(10f, 4f), CornerRadius(2f))
    }
    // Home: dark until the controller is fully charged, then it glows.
    val lit = if (charge >= 1f) 0.55f + 0.45f * surge else 0f
    if (lit > 0f) drawCircle(Neon.Magenta.copy(alpha = 0.30f * lit), 12f, GamepadArt.HOME)
    drawCircle(lerp(WELL, Neon.Magenta, lit), 6.5f, GamepadArt.HOME)
    drawCircle(Neon.Magenta.copy(alpha = 0.35f + 0.65f * charge), 6.5f, GamepadArt.HOME, style = Stroke(1.2f))
    for (dx in listOf(-7f, 0f, 7f)) drawCircle(Color.White.copy(alpha = 0.16f), 1.2f, Offset(160f + dx, 124f))
}

private fun DrawScope.drawDpad(art: GamepadArt, ms: Float) {
    val at = GamepadArt.DPAD
    drawCircle(WELL, 23f, at)
    drawCircle(Color.White.copy(alpha = 0.07f), 23f, at, style = Stroke(1f))
    drawPath(art.dpad, art.key)
    val right = GamepadTimeline.depth(Pad.DPadRight, ms)
    if (right > 0f) {
        drawRoundRect(Neon.Cyan.copy(alpha = right), Offset(at.x + 5f, at.y - 5.5f), Size(11f, 11f), CornerRadius(3f))
    }
    drawCircle(Color.Black.copy(alpha = 0.30f), 3.5f, at)
}

/** One face button: a dark seat, the coloured cap that sinks into it, and a small catch of light on top. */
private fun DrawScope.drawFaceButton(pad: Pad, ms: Float, charge: Float) {
    val at = GamepadArt.anchor(pad)
    val color = GamepadArt.tint(pad)
    val down = GamepadTimeline.depth(pad, ms)
    drawCircle(WELL, 10.5f, at + Offset(0f, 1.5f))
    val cap = at + Offset(0f, 1.5f * down)
    // Dim until pressed; once the whole controller is charged they all stay lit.
    val glow = maxOf(down, if (charge >= 1f) 0.75f else 0.35f)
    drawCircle(lerp(KEY_BOTTOM, color, glow), 9f * (1f - 0.10f * down), cap)
    drawCircle(color, 9f * (1f - 0.10f * down), cap, style = Stroke(1.2f))
    drawCircle(Color.White.copy(alpha = 0.45f), 2.4f, cap + Offset(-3f, -3.2f))
}

/**
 * One stick. A press rolls it once around its well ([turn] is the direction:
 * 1 clockwise, -1 the other way) while it is also pushed in.
 */
private fun DrawScope.drawStick(pad: Pad, ms: Float, turn: Float) {
    val at = GamepadArt.anchor(pad)
    val down = GamepadTimeline.depth(pad, ms)
    val around = GamepadTimeline.phase(pad, ms, GamepadTimeline.length(pad).toFloat()).coerceAtLeast(0f)
    val angle = turn * around * 2f * PI.toFloat() - PI.toFloat() / 2f
    val cap = at + Offset(cos(angle), sin(angle)) * (7f * down)
    drawCircle(WELL, 20f, at)
    drawCircle(Neon.Cyan.copy(alpha = 0.25f + 0.75f * down), 20f, at, style = Stroke(1.5f))
    drawCircle(Color.Black.copy(alpha = 0.45f), 14f, cap + Offset(0f, 2.5f))
    drawCircle(Brush.radialGradient(listOf(KEY_TOP, KEY_BOTTOM), center = cap - Offset(4f, 5f), radius = 20f), 14f, cap)
    drawCircle(lerp(Color.White.copy(alpha = 0.14f), Neon.Cyan, down), 14f, cap, style = Stroke(1.2f))
    // The thumb's hollow.
    drawCircle(Color.Black.copy(alpha = 0.30f), 8f, cap)
    drawCircle(Color.White.copy(alpha = 0.10f), 8f, cap, style = Stroke(1f))
}

/** What a press throws off: a ring that grows and thins, and six short sparks flying outwards. */
private fun DrawScope.drawSparks(pad: Pad, ms: Float) {
    val p = GamepadTimeline.phase(pad, ms, GamepadTimeline.SPARK_MS.toFloat())
    if (p < 0f) return
    val at = GamepadArt.anchor(pad)
    val color = GamepadArt.tint(pad)
    val out = 1f - (1f - p) * (1f - p) * (1f - p)
    val fade = 1f - p
    drawCircle(color.copy(alpha = 0.80f * fade), 10f + 20f * out, at, style = Stroke(0.5f + 2.5f * fade))
    for (i in 0 until 6) {
        val angle = (i * 60f + pad.ordinal * 23f) * PI.toFloat() / 180f
        val dir = Offset(cos(angle), sin(angle))
        val from = 13f + 27f * out
        drawLine(color.copy(alpha = fade), at + dir * from, at + dir * (from + 7f * fade), strokeWidth = 1.8f, cap = StrokeCap.Round)
    }
}
