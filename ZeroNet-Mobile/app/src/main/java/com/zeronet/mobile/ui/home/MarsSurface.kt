package com.zeronet.mobile.ui.home

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Mars as it looks: the real dark and bright regions where they really are, the
 * great volcanoes of Tharsis, the canyon of Valles Marineris, the Hellas and
 * Argyre basins, the ice at both poles, and a scatter of craters, lit from the
 * upper left with the limb dimmed and a butterscotch haze at the edge.
 *
 * How much of it is drawn depends on how big Mars looks (see [Lod]): small,
 * it is a shaded rust-red disc with its caps; larger, the big regions and the
 * canyon come in; close, every crater, volcano and wisp of cloud.
 */

/** A region on the surface: latitude and longitude (east) of its centre, angular radius in degrees, and how dark (negative) or bright (positive). */
internal data class Region(val lat: Float, val lon: Float, val radius: Float, val tone: Float)

// The dark regions and the bright ones, from the standard albedo map.
internal val MARS_DARK = listOf(
    Region(9f, 70f, 11f, -0.55f), // Syrtis Major
    Region(47f, 340f, 15f, -0.42f), // Acidalia
    Region(0f, 0f, 6f, -0.42f), // Meridiani
    Region(-25f, 325f, 10f, -0.42f), // Erythraeum
    Region(-26f, 270f, 6f, -0.5f), // Solis Lacus
    Region(-20f, 215f, 11f, -0.42f), // Cimmerium
    Region(-35f, 200f, 11f, -0.36f), // Sirenum
    Region(62f, 30f, 12f, -0.26f), // the northern plains
    Region(62f, 120f, 12f, -0.26f),
    Region(62f, 210f, 12f, -0.26f),
    Region(62f, 300f, 12f, -0.26f),
)
internal val MARS_BRIGHT = listOf(
    Region(-42f, 70f, 9f, 0.5f), // Hellas
    Region(-50f, 318f, 5f, 0.5f), // Argyre
    Region(13f, 87f, 5f, 0.28f), // Isidis
    Region(20f, 240f, 16f, 0.22f), // Tharsis
    Region(-5f, 165f, 14f, 0.24f), // Elysium and the plains around it
)
private val VOLCANOES = listOf(
    Region(18.6f, 226f, 4.4f, 0f), // Olympus Mons
    Region(11.8f, 255.5f, 2.5f, 0f), // Ascraeus
    Region(1.5f, 247f, 2.5f, 0f), // Pavonis
    Region(-9f, 239f, 2.5f, 0f), // Arsia
)
private val CANYON = listOf(-6f to 286f, -9f to 295f, -12f to 304f, -13.5f to 313f, -12f to 322f)

private val ROCK = Color(0xFFC1622F)
private val OCHRE = Color(0xFFDDA268)
private val BASALT = Color(0xFF5E2A1A)
private val ICE = Color(0xFFF6F1EA)

/** The camera onto Mars: spinning slowly, tipped a little toward us. */
private class View(val camera: GlobeCamera, val center: Offset, val r: Float) {
    /** Screen position of a point on the surface and its depth (positive faces us). */
    fun at(lat: Float, lon: Float): Triple<Offset, Float, FloatArray> {
        val u = unitVector(lat, lon)
        val sx = u[0] * camera.ex + u[1] * camera.ey + u[2] * camera.ez
        val sy = u[0] * camera.nx + u[1] * camera.ny + u[2] * camera.nz
        val depth = u[0] * camera.vx + u[1] * camera.vy + u[2] * camera.vz
        return Triple(Offset(center.x + sx * r, center.y - sy * r), depth, u)
    }
}

/** How much to draw a feature near the edge: it thins out toward the limb. */
private fun edge(depth: Float) = (depth * 2.6f).coerceIn(0f, 1f)

/** A circle on the surface of angular radius [degrees] around a point, as a path on the disc. */
private fun View.cap(lat: Float, lon: Float, degrees: Float, steps: Int = 72, wobble: Float = 0f): Path? {
    val (_, depth, u) = at(lat, lon)
    if (depth < -0.4f) return null
    val ax = if (abs(u[2]) < 0.9f) 0f else 1f
    val az = if (abs(u[2]) < 0.9f) 1f else 0f
    var t1x = -az * u[1]
    var t1y = az * u[0] - ax * u[2]
    var t1z = ax * u[1]
    val n1 = sqrt(t1x * t1x + t1y * t1y + t1z * t1z).coerceAtLeast(1e-6f)
    t1x /= n1; t1y /= n1; t1z /= n1
    val t2x = u[1] * t1z - u[2] * t1y
    val t2y = u[2] * t1x - u[0] * t1z
    val t2z = u[0] * t1y - u[1] * t1x
    val path = Path()
    for (k in 0..steps) {
        val theta = k * 2f * PI.toFloat() / steps
        // A ragged edge for ice and cloud; a clean one for basins.
        val rr = (degrees * (1f + wobble * sin(theta * 2f + lat) * cos(theta * 3f + lon))) * (PI.toFloat() / 180f)
        val cr = cos(rr); val sr = sin(rr)
        val ct = cos(theta); val st = sin(theta)
        val x = cr * u[0] + sr * (ct * t1x + st * t2x)
        val y = cr * u[1] + sr * (ct * t1y + st * t2y)
        val z = cr * u[2] + sr * (ct * t1z + st * t2z)
        var sx = x * camera.ex + y * camera.ey + z * camera.ez
        var sy = x * camera.nx + y * camera.ny + z * camera.nz
        val d = x * camera.vx + y * camera.vy + z * camera.vz
        if (d < 0f) {
            // Round the far side onto the limb.
            val len = sqrt(sx * sx + sy * sy).coerceAtLeast(1e-6f)
            sx /= len; sy /= len
        }
        val p = Offset(center.x + sx * r, center.y - sy * r)
        if (k == 0) path.moveTo(p.x, p.y) else path.lineTo(p.x, p.y)
    }
    path.close()
    return path
}

/**
 * Mars at [scale] of the globe's size, at [ms] on the animation clock.
 * [dark] only changes how heavy the night side is.
 */
fun DrawScope.drawMars(center: Offset, radius: Float, scale: Float, ms: Float, dark: Boolean) {
    if (scale <= 0.01f) return
    val r = radius * scale
    val unit = r / 134f
    val detail = Lod.of(r / density)
    val seconds = ms / 1000f

    // Turning once a minute, tipped 14 degrees toward us.
    val camera = GlobeCamera().apply { lookAt(14f, 40f + seconds * 6f) }
    val view = View(camera, center, r)
    val light = Offset(center.x - r * 0.38f, center.y - r * 0.42f)

    // The haze first, so the disc sits in it.
    drawCircle(
        Brush.radialGradient(
            0.82f to Color.Transparent,
            0.94f to Color(0xFFE39A64).copy(alpha = 0.22f + 0.10f * detail.medium),
            1f to Color.Transparent,
            center = center, radius = r * 1.2f,
        ),
        r * 1.2f, center,
    )
    marsMoons(center, r, seconds, front = false)

    // The disc: rust in the light, dark red at the edge.
    drawCircle(
        Brush.radialGradient(0f to Color(0xFFE28A57), 0.55f to ROCK, 1f to Color(0xFF64281A), center = light, radius = r * 1.5f),
        r, center,
    )

    val disc = Path().apply { addOval(Rect(center.x - r, center.y - r, center.x + r, center.y + r)) }
    clipPath(disc) {
        // Regions: soft-edged, two passes each, so they blend into the ground.
        fun region(reg: Region, fade: Float, colour: Color) {
            val (_, depth, _) = view.at(reg.lat, reg.lon)
            val e = edge(depth) * fade
            if (e <= 0.01f) return
            val alpha = abs(reg.tone) * e
            view.cap(reg.lat, reg.lon, reg.radius * 1.7f, wobble = 0.10f)?.let { drawPath(it, colour.copy(alpha = alpha * 0.22f)) }
            view.cap(reg.lat, reg.lon, reg.radius * 1.3f, wobble = 0.13f)?.let { drawPath(it, colour.copy(alpha = alpha * 0.32f)) }
            view.cap(reg.lat, reg.lon, reg.radius, wobble = 0.16f)?.let { drawPath(it, colour.copy(alpha = alpha * 0.50f)) }
        }
        if (detail.medium > 0.01f) {
            MARS_BRIGHT.forEach { region(it, detail.medium, OCHRE) }
            MARS_DARK.forEach { region(it, detail.medium, BASALT) }
        } else {
            // Far away: two dark patches that turn with the planet, and that is all.
            region(MARS_DARK[0], 1f, BASALT)
            region(MARS_DARK[1], 1f, BASALT)
        }

        if (detail.medium > 0.01f) {
            // Tharsis: four volcanoes, each a pale slope with a dark crater on top.
            for (v in VOLCANOES) {
                val (_, depth, _) = view.at(v.lat, v.lon)
                val e = edge(depth) * detail.medium
                if (e <= 0.01f) continue
                view.cap(v.lat, v.lon, v.radius * 1.6f)?.let { drawPath(it, OCHRE.copy(alpha = 0.40f * e)) }
                view.cap(v.lat, v.lon, v.radius)?.let { drawPath(it, Color(0xFFE9A878).copy(alpha = 0.45f * e)) }
                view.cap(v.lat, v.lon, v.radius * 0.3f, steps = 24)?.let { drawPath(it, BASALT.copy(alpha = 0.7f * e)) }
            }
            // Valles Marineris: a long crack, with its lit wall.
            val canyon = Path()
            var started = false
            var facing = 1f
            CANYON.forEach { (lat, lon) ->
                val (p, depth, _) = view.at(lat, lon)
                facing = minOf(facing, depth)
                if (depth < 0f) return@forEach
                if (!started) { canyon.moveTo(p.x, p.y); started = true } else canyon.lineTo(p.x, p.y)
            }
            if (started) {
                val e = edge(facing + 0.15f) * detail.medium
                drawPath(canyon, BASALT.copy(alpha = 0.60f * e), style = Stroke(3.2f * unit, cap = StrokeCap.Round, join = StrokeJoin.Round))
                drawPath(canyon, Color(0xFFF0B080).copy(alpha = 0.30f * e), style = Stroke(1.0f * unit, cap = StrokeCap.Round, join = StrokeJoin.Round))
            }
        }

        if (detail.fine > 0.01f) {
            // Craters: a dark floor and a bright rim on the sunlit side.
            var seed = 0x2545F4914F6CDD1DL
            fun rand(): Float {
                seed = seed xor (seed shl 13); seed = seed xor (seed ushr 7); seed = seed xor (seed shl 17)
                return ((seed ushr 11) and 0xFFFFFF).toFloat() / 0x1000000.toFloat()
            }
            repeat(90) {
                val lat = (asin(2f * rand() - 1f) * 180f / PI.toFloat())
                val lon = rand() * 360f
                val size = 0.8f + 3.6f * rand() * rand()
                val (p, depth, _) = view.at(lat, lon)
                val e = edge(depth) * detail.fine
                if (e <= 0.02f) return@repeat
                val squash = depth.coerceAtLeast(0.1f)
                val rad = size * (PI.toFloat() / 180f) * r
                view.cap(lat, lon, size, steps = 24)?.let {
                    drawPath(it, BASALT.copy(alpha = 0.34f * e))
                    drawPath(it, Color(0xFFF2B98A).copy(alpha = 0.34f * e), style = Stroke(0.7f * unit))
                }
                if (rad * squash > 2.4f * unit) {
                    drawCircle(Color(0xFFF7C9A0).copy(alpha = 0.22f * e), rad * 0.22f, Offset(p.x - rad * 0.3f * squash, p.y - rad * 0.3f))
                }
            }
            // Water-ice cloud over the volcanoes and along the northern edge of the cap.
            val cloud = Color(0xFFFFF4E8)
            for ((lat, lon, size) in listOf(Triple(18f, 226f, 9f), Triple(70f, 40f, 16f), Triple(-62f, 250f, 14f), Triple(35f, 120f, 8f))) {
                val (_, depth, _) = view.at(lat, lon)
                val e = edge(depth) * detail.fine
                if (e <= 0.02f) continue
                view.cap(lat, lon, size * 1.6f, wobble = 0.3f)?.let { drawPath(it, cloud.copy(alpha = 0.06f * e)) }
                view.cap(lat, lon, size, wobble = 0.3f)?.let { drawPath(it, cloud.copy(alpha = 0.10f * e)) }
            }
        }

        // The ice at the poles: a ragged edge close up, a clean cap far off.
        val ragged = 0.05f + 0.20f * detail.fine
        view.cap(90f, 0f, 12f + 3f * detail.fine, wobble = ragged)?.let { drawPath(it, ICE.copy(alpha = 0.55f)) }
        view.cap(90f, 0f, 8.5f, wobble = ragged)?.let { drawPath(it, ICE.copy(alpha = 0.95f)) }
        view.cap(-90f, 0f, 9f, wobble = ragged)?.let { drawPath(it, ICE.copy(alpha = 0.55f)) }
        view.cap(-90f, 0f, 6.5f, wobble = ragged)?.let { drawPath(it, ICE.copy(alpha = 0.92f)) }

        // Sunlight: the far side of the light falls into shadow, and the limb dims.
        drawCircle(
            Brush.radialGradient(
                0.55f to Color.Transparent,
                1f to Color.Black.copy(alpha = if (dark) 0.58f else 0.32f),
                center = light, radius = r * 1.75f,
            ),
            r, center,
        )
        drawCircle(
            Brush.radialGradient(0.70f to Color.Transparent, 1f to Color(0xFF3A120A).copy(alpha = 0.38f), center = center, radius = r),
            r, center,
        )
    }
    // A thin bright rim where the haze catches the light.
    drawCircle(Color(0xFFF7B682).copy(alpha = 0.50f), r, center, style = Stroke(1.3f * unit))
    drawArc(
        Color(0xFFFFE2C0).copy(alpha = 0.45f), 195f, 70f, false,
        Offset(center.x - r, center.y - r), androidx.compose.ui.geometry.Size(2 * r, 2 * r), style = Stroke(2.2f * unit, cap = StrokeCap.Round),
    )

    marsMoons(center, r, seconds, front = true)
}
