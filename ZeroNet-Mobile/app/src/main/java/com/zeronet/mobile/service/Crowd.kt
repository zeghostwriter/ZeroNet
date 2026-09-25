package com.zeronet.mobile.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import android.util.Log
import com.zeronet.mobile.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

/**
 * What other ZeroNet users found: which public servers and clean Cloudflare
 * addresses work on which network (see deploy/crowd-relay/README.md).
 *
 * Reading: `rankings.json` is published on the repository's `crowd-data`
 * branch by the `crowd` GitHub Action and fetched from GitHub or its
 * jsDelivr mirror, kept on disk and refreshed every [TTL_MS].
 *
 * Writing: after a connection attempt the engine reports what its tests
 * found, public servers only, to a relay named in the rankings. Reports go
 * straight out on the phone's own network (the app is excluded from its VPN),
 * so for Wi-Fi the relay can tell the ISP; it answers with the network name
 * it used, which is remembered for this Wi-Fi.
 */
object Crowd {
    private const val TAG = "Crowd"
    private const val TTL_MS = 20 * 60 * 1000L
    private const val REPO = "zeghostwriter/ZeroNet"
    private val RANKING_URLS = listOf(
        "https://raw.githubusercontent.com/$REPO/crowd-data/rankings.json",
        "https://cdn.jsdelivr.net/gh/$REPO@crowd-data/rankings.json",
        "https://fastly.jsdelivr.net/gh/$REPO@crowd-data/rankings.json",
    )
    /** At most this many results per report, as the relay accepts. */
    const val MAX_RESULTS = 40
    const val MAX_CLEAN = 10
    private const val ALL = "all"

    data class Pick(val id: String, val link: String, val score: Double, val ms: Int)
    data class Result(val id: String, val ok: Boolean, val ms: Int)
    data class CleanIp(val ip: String, val ms: Int)

    private fun file(context: Context) = File(File(context.cacheDir, "crowd").apply { mkdirs() }, "rankings.json")
    private fun prefs(context: Context) = context.getSharedPreferences("crowd", Context.MODE_PRIVATE)

    // ------------------------------------------------------------ network

    /**
     * The shared name of the network: the carrier's MCC+MNC on mobile data,
     * otherwise what the relay called this network (by its ISP) the last
     * time a report was sent from it, otherwise "all".
     */
    fun networkName(context: Context, localNetwork: String): String =
        carrier(context)?.let { "cell:$it" }
            ?: prefs(context).getString("net:$localNetwork", null)
            ?: ALL

    /** MCC+MNC of the mobile network carrying traffic now, or null on Wi-Fi and the like. */
    fun carrier(context: Context): String? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) } ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return null
        val code = context.getSystemService(TelephonyManager::class.java)?.networkOperator.orEmpty()
        return code.takeIf { it.length in 5..6 && it.all(Char::isDigit) }
    }

    // ------------------------------------------------------------ reading

    /**
     * The rankings, from disk if fresh, else downloaded (straight out, then
     * through [tunnel] when given). A failed download falls back to the file
     * on disk however old it is.
     */
    fun rankings(context: Context, tunnel: Proxy?, timeoutMs: Int): JSONObject? {
        val cached = file(context)
        val age = System.currentTimeMillis() - cached.lastModified()
        if (cached.exists() && age < TTL_MS) return read(cached)
        val routes = listOfNotNull(Proxy.NO_PROXY, tunnel)
        for (route in routes) {
            for (url in RANKING_URLS) {
                val text = runCatching { get(url, route, timeoutMs) }.getOrNull() ?: continue
                val parsed = runCatching { JSONObject(text) }.getOrNull() ?: continue
                if (parsed.optInt("v") != 1) continue
                runCatching {
                    val tmp = File(cached.parentFile, "rankings.tmp")
                    tmp.writeText(text)
                    tmp.renameTo(cached)
                }
                return parsed
            }
        }
        return if (cached.exists()) read(cached) else null
    }

    private fun read(file: File): JSONObject? = runCatching { JSONObject(file.readText()) }.getOrNull()

    /** The servers others got through with on [network], best first, then the overall list. */
    fun picks(rankings: JSONObject, network: String, limit: Int): List<Pick> {
        val nets = rankings.optJSONObject("nets") ?: return emptyList()
        val out = LinkedHashMap<String, Pick>()
        for (name in listOf(network, ALL).distinct()) {
            val servers = nets.optJSONObject(name)?.optJSONArray("servers") ?: continue
            for (i in 0 until servers.length()) {
                val s = servers.optJSONObject(i) ?: continue
                val id = s.optString("id")
                val link = s.optString("link")
                if (id.isEmpty() || link.isEmpty() || id in out) continue
                out[id] = Pick(id, link, s.optDouble("score"), s.optInt("ms", -1))
                if (out.size >= limit) return out.values.toList()
            }
        }
        return out.values.toList()
    }

    /** Clean Cloudflare addresses others found on [network]. */
    fun cleanIps(rankings: JSONObject, network: String): List<CleanIp> {
        val nets = rankings.optJSONObject("nets") ?: return emptyList()
        val list = nets.optJSONObject(network)?.optJSONArray("clean_ips")
            ?: nets.optJSONObject(ALL)?.optJSONArray("clean_ips")
            ?: return emptyList()
        return (0 until list.length()).mapNotNull { i ->
            list.optJSONObject(i)?.let { CleanIp(it.optString("ip"), it.optInt("ms", -1)) }?.takeIf { it.ip.isNotEmpty() }
        }
    }

    // ------------------------------------------------------------ writing

    /**
     * Send [results] and [clean] for [localNetwork]. Blocking; call off the
     * main thread. Quietly does nothing when no relay is known or none
     * answers: sharing must never get in the way of connecting.
     */
    fun report(context: Context, localNetwork: String, results: List<Result>, clean: List<CleanIp>, tunnel: Proxy?) {
        if (results.isEmpty() && clean.isEmpty()) return
        val relays = read(file(context))?.optJSONArray("relays")?.let { a -> List(a.length()) { a.optString(it) } }
            ?.filter { it.startsWith("https://") }.orEmpty()
        if (relays.isEmpty()) return
        val carrier = carrier(context)
        val body = JSONObject()
            .put("v", 1)
            .put("results", JSONArray().also { a -> results.take(MAX_RESULTS).forEach { a.put(JSONObject().put("id", it.id).put("ok", it.ok).put("ms", it.ms)) } })
            .put("clean", JSONArray().also { a -> clean.take(MAX_CLEAN).forEach { a.put(JSONObject().put("ip", it.ip).put("ms", it.ms)) } })
        if (carrier != null) body.put("net", "cell:$carrier")
        // Straight out first, so the relay sees this network's ISP. Through
        // the tunnel only when the network is named in the report itself:
        // otherwise it would be counted under the VPN server's ISP.
        val routes = listOfNotNull(Proxy.NO_PROXY, tunnel?.takeIf { carrier != null })
        for (route in routes) {
            for (relay in relays) {
                val answer = runCatching { post("$relay/v1/report", body.toString(), route) }
                    .onFailure { Log.i(TAG, "report to $relay: ${it.message}") }
                    .getOrNull() ?: continue
                runCatching { JSONObject(answer).optString("net") }.getOrNull()
                    ?.takeIf { it.startsWith("asn:") && carrier == null && route == Proxy.NO_PROXY }
                    ?.let { prefs(context).edit().putString("net:$localNetwork", it).apply() }
                return
            }
        }
    }

    // ------------------------------------------------------------ HTTP

    private fun open(url: String, proxy: Proxy, timeoutMs: Int): HttpURLConnection =
        (URL(url).openConnection(proxy) as HttpURLConnection).apply {
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "ZeroNet-Android/${BuildConfig.VERSION_NAME}")
        }

    private fun get(url: String, proxy: Proxy, timeoutMs: Int): String {
        val conn = open(url, proxy, timeoutMs)
        try {
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            return conn.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
    }

    private fun post(url: String, body: String, proxy: Proxy): String {
        val conn = open(url, proxy, 8_000)
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.outputStream.use { it.write(body.toByteArray()) }
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            return conn.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
    }
}
