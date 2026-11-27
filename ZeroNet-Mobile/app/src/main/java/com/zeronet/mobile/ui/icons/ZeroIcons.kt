package com.zeronet.mobile.ui.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * The app's icon set: a small, consistent 24-dp outline family drawn here
 * instead of pulling in material-icons-extended (several MB). Strokes are
 * 1.8 units with round caps and joins; icons tint through `LocalContentColor`.
 */
object ZeroIcons {
    private const val STROKE = 1.8f

    private fun icon(name: String, autoMirror: Boolean = false, vararg paths: String, filled: List<String> = emptyList()): ImageVector {
        val b = ImageVector.Builder(
            name = name,
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
            autoMirror = autoMirror,
        )
        paths.forEach { d ->
            b.addPath(
                pathData = addPathNodes(d),
                fill = null,
                stroke = SolidColor(Color.Black),
                strokeLineWidth = STROKE,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round,
            )
        }
        filled.forEach { d ->
            b.addPath(pathData = addPathNodes(d), fill = SolidColor(Color.Black), pathFillType = PathFillType.EvenOdd)
        }
        return b.build()
    }

    private fun f(v: Double) = "%.3f".format(java.util.Locale.US, v)

    /** A regular star polygon as an SVG path (5 points for the favourite star). */
    private fun starPath(points: Int, outer: Double, inner: Double, cx: Double = 12.0, cy: Double = 12.3): String {
        val sb = StringBuilder()
        for (i in 0 until points * 2) {
            val r = if (i % 2 == 0) outer else inner
            val a = -PI / 2 + i * PI / points
            sb.append(if (i == 0) "M" else "L").append(f(cx + r * cos(a))).append(' ').append(f(cy + r * sin(a)))
        }
        return sb.append('Z').toString()
    }

    /** A cog outline with [teeth] flat-topped teeth. */
    private fun gearPath(teeth: Int = 8, outer: Double = 9.6, inner: Double = 7.4): String {
        val sb = StringBuilder()
        val step = 2 * PI / teeth
        val half = step * 0.22
        for (i in 0 until teeth) {
            val c = -PI / 2 + i * step
            val pts = listOf(
                inner to c - step / 2 + half * 0.6,
                inner to c - half * 1.25,
                outer to c - half * 0.8,
                outer to c + half * 0.8,
                inner to c + half * 1.25,
            )
            pts.forEachIndexed { j, (r, a) ->
                sb.append(if (i == 0 && j == 0) "M" else "L").append(f(12 + r * cos(a))).append(' ').append(f(12 + r * sin(a)))
            }
        }
        return sb.append('Z').toString()
    }

    private const val CIRCLE_3 = "M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"

    val Home = icon("home", false, "M3.5 10.5 12 3.5l8.5 7", "M5.5 9v10.5a1 1 0 0 0 1 1H10v-5.5h4v5.5h3.5a1 1 0 0 0 1-1V9")
    val Globe = icon(
        "globe", false,
        "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
        "M3.5 9h17", "M3.5 15h17",
        "M12 3c2.4 2.6 3.6 5.6 3.6 9s-1.2 6.4-3.6 9c-2.4-2.6-3.6-5.6-3.6-9S9.6 5.6 12 3Z",
    )
    val Radar = icon(
        "radar", false,
        "M20.5 12A8.5 8.5 0 1 1 12 3.5",
        "M16.5 12A4.5 4.5 0 1 1 12 7.5",
        "M12 12l6.2-6.2",
        filled = listOf("M13.4 12a1.4 1.4 0 1 1-2.8 0 1.4 1.4 0 0 1 2.8 0Z"),
    )
    val Settings = icon("settings", false, gearPath(), CIRCLE_3)
    val Star = icon("star", false, starPath(5, 9.2, 4.0))
    val StarFilled = icon("star_filled", false, starPath(5, 9.2, 4.0), filled = listOf(starPath(5, 9.2, 4.0)))
    val Search = icon("search", true, "M17.5 10.75a6.75 6.75 0 1 1-13.5 0 6.75 6.75 0 0 1 13.5 0Z", "M15.6 15.6 20.5 20.5")
    val Refresh = icon("refresh", false, "M19.5 12a7.5 7.5 0 1 1-2.2-5.3", "M19.5 4v4h-4")
    val Share = icon(
        "share", false,
        "M20 5.5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0Z",
        "M9 12a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0Z",
        "M20 18.5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0Z",
        "M8.7 10.8l6-3.6", "M8.7 13.2l6 3.6",
    )
    val Copy = icon(
        "copy", false,
        "M11 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2Z",
        "M5.5 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v.5",
    )
    val Qr = icon(
        "qr", false,
        "M4 4h6v6H4Z", "M14 4h6v6h-6Z", "M4 14h6v6H4Z",
        "M14 14h2.5", "M14 17v3", "M17 17h3", "M20 14v1", "M17 20h3",
    )
    val Close = icon("close", false, "M6 6l12 12", "M18 6 6 18")
    val ChevronEnd = icon("chevron_end", true, "M9.5 6l6 6-6 6")
    val ChevronDown = icon("chevron_down", false, "M6 9.5l6 6 6-6")
    val Back = icon("back", true, "M19 12H5", "M11 18l-6-6 6-6")
    val Check = icon("check", false, "M5 12.5l4.5 4.5L19 7.5")
    val Bolt = icon("bolt", false, "M13 2.5 4.5 13.5H11l-1 8 8.5-11H12l1-8Z")
    val Shield = icon("shield", false, "M12 3 5 6v5.2c0 4.3 2.9 8.2 7 9.8 4.1-1.6 7-5.5 7-9.8V6l-7-3Z", "M9 12l2 2 4-4")
    val Wifi = icon(
        "wifi", false,
        "M2.5 8.8a14 14 0 0 1 19 0", "M5.5 12.2a9.5 9.5 0 0 1 13 0", "M8.6 15.5a5 5 0 0 1 6.8 0",
        filled = listOf("M13.3 19a1.3 1.3 0 1 1-2.6 0 1.3 1.3 0 0 1 2.6 0Z"),
    )
    val Trash = icon(
        "trash", false,
        "M4 6.5h16", "M10 11v6", "M14 11v6",
        "M6 6.5l.9 12.6a2 2 0 0 0 2 1.9h6.2a2 2 0 0 0 2-1.9L18 6.5",
        "M9 6.5V4.5A1.5 1.5 0 0 1 10.5 3h3A1.5 1.5 0 0 1 15 4.5v2",
    )
    val Plus = icon("plus", false, "M12 5v14", "M5 12h14")
    val Paste = icon(
        "paste", false,
        "M9 3h6a1 1 0 0 1 1 1v1.5a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z",
        "M16 4.5h1.5A1.5 1.5 0 0 1 19 6v13.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19.5V6a1.5 1.5 0 0 1 1.5-1.5H8",
        "M9 12h6", "M9 16h4",
    )
    val Info = icon("info", false, "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", "M12 11v5.5", filled = listOf("M13.1 7.8a1.1 1.1 0 1 1-2.2 0 1.1 1.1 0 0 1 2.2 0Z"))
    val ArrowDown = icon("arrow_down", false, "M12 5v14", "M6.5 13.5 12 19l5.5-5.5")
    val ArrowUp = icon("arrow_up", false, "M12 19V5", "M6.5 10.5 12 5l5.5 5.5")
    val Link = icon(
        "link", false,
        "M10 13.5a4.5 4.5 0 0 0 6.4.4l2.7-2.7a4.5 4.5 0 0 0-6.4-6.4L11.2 6.3",
        "M14 10.5a4.5 4.5 0 0 0-6.4-.4l-2.7 2.7a4.5 4.5 0 0 0 6.4 6.4l1.5-1.5",
    )
    val Lock = icon("lock", false, "M6.5 10.5h11a1.5 1.5 0 0 1 1.5 1.5v7a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19v-7a1.5 1.5 0 0 1 1.5-1.5Z", "M8 10.5V7.5a4 4 0 0 1 8 0v3")
    val Split = icon("split", false, "M12 21v-6.5", "M12 14.5 6.5 9V4", "M12 14.5 17.5 9V4", "M4 6l2.5-2.5L9 6", "M15 6l2.5-2.5L20 6")
    val Palette = icon(
        "palette", false,
        "M12 3a9 9 0 0 0 0 18c1.2 0 1.8-.8 1.8-1.7 0-.5-.2-.9-.5-1.3-.3-.4-.5-.8-.5-1.3 0-.9.8-1.7 1.7-1.7H16a5 5 0 0 0 5-5C21 6.6 17 3 12 3Z",
        filled = listOf(
            "M8.8 9a1.2 1.2 0 1 1-2.4 0 1.2 1.2 0 0 1 2.4 0Z",
            "M12.7 6.9a1.2 1.2 0 1 1-2.4 0 1.2 1.2 0 0 1 2.4 0Z",
            "M17 9a1.2 1.2 0 1 1-2.4 0 1.2 1.2 0 0 1 2.4 0Z",
            "M8 13.3a1.2 1.2 0 1 1-2.4 0 1.2 1.2 0 0 1 2.4 0Z",
        ),
    )
    val Apps = icon(
        "apps", false,
        "M5.5 4h3A1.5 1.5 0 0 1 10 5.5v3A1.5 1.5 0 0 1 8.5 10h-3A1.5 1.5 0 0 1 4 8.5v-3A1.5 1.5 0 0 1 5.5 4Z",
        "M15.5 4h3A1.5 1.5 0 0 1 20 5.5v3a1.5 1.5 0 0 1-1.5 1.5h-3A1.5 1.5 0 0 1 14 8.5v-3A1.5 1.5 0 0 1 15.5 4Z",
        "M5.5 14h3a1.5 1.5 0 0 1 1.5 1.5v3A1.5 1.5 0 0 1 8.5 20h-3A1.5 1.5 0 0 1 4 18.5v-3A1.5 1.5 0 0 1 5.5 14Z",
        "M15.5 14h3a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5h-3a1.5 1.5 0 0 1-1.5-1.5v-3a1.5 1.5 0 0 1 1.5-1.5Z",
    )
    val External = icon("external", true, "M14 4h6v6", "M20 4l-8.5 8.5", "M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10")
    val Clock = icon("clock", false, "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", "M12 7v5l3 2")
    val Sliders = icon("sliders", false, "M4 7h9", "M17 7h3", "M4 17h3", "M11 17h9", "M17 7a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z", "M11 17a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z")
    val Signal = icon("signal", false, "M5 19v-3", "M10 19v-7", "M15 19v-11", "M20 19V5")
    val Bell = icon(
        "bell", false,
        "M18 16.5H6l1.2-1.6a2 2 0 0 0 .4-1.2V10a4.4 4.4 0 0 1 8.8 0v3.7a2 2 0 0 0 .4 1.2L18 16.5Z",
        "M10 19.5a2.1 2.1 0 0 0 4 0",
    )
}
