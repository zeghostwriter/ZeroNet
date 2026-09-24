package com.zeronet.mobile.ui.home

import android.content.Context
import android.telephony.TelephonyManager
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/** A point on the Earth, in degrees. */
data class LatLon(val lat: Float, val lon: Float)

/**
 * Polylines on the unit sphere, flattened: [xyz] holds x, y, z per point and
 * [starts] the first point of each line, with a final entry equal to the
 * point count.
 */
class SpherePolylines(val xyz: FloatArray, val starts: IntArray) {
    val lineCount: Int get() = starts.size - 1
}

/**
 * What the globe draws: coastlines from Natural Earth's 1:110m land polygons
 * (public domain), a 15° graticule, and a label point per country for the
 * route's ends. Loaded once from `assets/globe/`.
 */
class GlobeData(
    val coast: SpherePolylines,
    val graticule: SpherePolylines,
    private val countries: Map<String, LatLon>,
) {
    /** Where to draw a country: its label point, or null when unknown. */
    fun country(code: String): LatLon? = countries[code.uppercase(Locale.ROOT)]

    companion object {
        @Volatile private var cached: GlobeData? = null

        fun load(context: Context): GlobeData = cached ?: synchronized(this) {
            cached ?: read(context).also { cached = it }
        }

        private fun read(context: Context): GlobeData {
            val bytes = context.assets.open("globe/land.bin").use { it.readBytes() }
            val coast = decodeLand(bytes)
            val countries = context.assets.open("globe/countries.txt").bufferedReader().useLines { lines ->
                lines.filter { it.isNotBlank() && !it.startsWith("#") }
                    .mapNotNull { line ->
                        val parts = line.trim().split(' ')
                        if (parts.size < 3) return@mapNotNull null
                        val lat = parts[1].toFloatOrNull() ?: return@mapNotNull null
                        val lon = parts[2].toFloatOrNull() ?: return@mapNotNull null
                        parts[0] to LatLon(lat, lon)
                    }
                    .toMap()
            }
            return GlobeData(coast, graticule(), countries)
        }

        /** `land.bin`: u16 ring count, then per ring a u16 point count and i16 lat, lon in 1/100 degree. */
        private fun decodeLand(bytes: ByteArray): SpherePolylines {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val rings = buf.short.toInt() and 0xFFFF
            val starts = IntArray(rings + 1)
            val points = ArrayList<Float>(16_000)
            var count = 0
            for (r in 0 until rings) {
                starts[r] = count
                val n = buf.short.toInt() and 0xFFFF
                repeat(n) {
                    val lat = buf.short / 100f
                    val lon = buf.short / 100f
                    addUnit(points, lat, lon)
                    count++
                }
            }
            starts[rings] = count
            return SpherePolylines(points.toFloatArray(), starts)
        }

        /** Meridians every 15° and parallels every 15°, sampled every 3°. */
        private fun graticule(): SpherePolylines {
            val points = ArrayList<Float>(12_000)
            val starts = ArrayList<Int>()
            var count = 0
            for (lon in -180 until 180 step 15) {
                starts += count
                for (lat in -84..84 step 3) { addUnit(points, lat.toFloat(), lon.toFloat()); count++ }
            }
            for (lat in -75..75 step 15) {
                starts += count
                for (lon in -180..180 step 3) { addUnit(points, lat.toFloat(), lon.toFloat()); count++ }
            }
            starts += count
            return SpherePolylines(points.toFloatArray(), starts.toIntArray())
        }

        private fun addUnit(out: ArrayList<Float>, lat: Float, lon: Float) {
            val v = unitVector(lat, lon)
            out += v[0]; out += v[1]; out += v[2]
        }
    }
}

private const val DEG = (PI / 180.0).toFloat()

/** The unit vector for a latitude/longitude (x toward 0°E, z toward the North Pole). */
fun unitVector(lat: Float, lon: Float): FloatArray {
    val phi = lat * DEG
    val lambda = lon * DEG
    return floatArrayOf(cos(phi) * cos(lambda), cos(phi) * sin(lambda), sin(phi))
}

/** The latitude/longitude of a (not necessarily unit) vector. */
fun latLonOf(v: FloatArray): LatLon {
    val len = sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).coerceAtLeast(1e-6f)
    val lat = kotlin.math.asin((v[2] / len).coerceIn(-1f, 1f)) / DEG
    val lon = atan2(v[1], v[0]) / DEG
    return LatLon(lat, lon)
}

/**
 * An orthographic camera looking at (lat0, lon0): screen x points east,
 * screen y north, depth toward the viewer. A point is on the visible
 * hemisphere when its depth is positive.
 */
class GlobeCamera {
    var ex = 0f; var ey = 0f; var ez = 0f
    var nx = 0f; var ny = 0f; var nz = 0f
    var vx = 0f; var vy = 0f; var vz = 0f

    fun lookAt(lat0: Float, lon0: Float) {
        val phi = lat0 * DEG
        val lambda = lon0 * DEG
        val sl = sin(lambda); val cl = cos(lambda)
        val sp = sin(phi); val cp = cos(phi)
        ex = -sl; ey = cl; ez = 0f
        nx = -sp * cl; ny = -sp * sl; nz = cp
        vx = cp * cl; vy = cp * sl; vz = sp
    }
}

/** Shortest-way interpolation between two longitudes, in degrees. */
fun lerpLongitude(from: Float, to: Float, t: Float): Float {
    var delta = (to - from) % 360f
    if (delta > 180f) delta -= 360f
    if (delta < -180f) delta += 360f
    return from + delta * t
}

/** Tehran for Iran (most users are near it); the country's label point otherwise. */
private val CAPITAL_OVERRIDES = mapOf("IR" to LatLon(35.69f, 51.39f))

/**
 * Where the user is, without asking for location: the country of the mobile
 * network (or SIM), falling back to the language region, and to Iran.
 */
fun userLocation(context: Context, data: GlobeData): LatLon {
    val tm = context.getSystemService(TelephonyManager::class.java)
    val candidates = listOf(
        runCatching { tm?.networkCountryIso }.getOrNull(),
        runCatching { tm?.simCountryIso }.getOrNull(),
        Locale.getDefault().country,
        "IR",
    )
    for (raw in candidates) {
        val code = raw?.trim()?.uppercase(Locale.ROOT).orEmpty()
        if (code.length != 2) continue
        CAPITAL_OVERRIDES[code]?.let { return it }
        data.country(code)?.let { return it }
    }
    return CAPITAL_OVERRIDES.getValue("IR")
}
