package com.zeronet.mobile.service

import android.content.Context
import com.zeronet.mobile.model.ConnectionProfile
import org.json.JSONArray
import org.json.JSONObject

/**
 * How well each mode does in real use, kept as a few anonymous facts and sent
 * with the crowd report when "Help others connect" is on.
 *
 * What is recorded, and all of it:
 *
 * * `<mode>:connect` – did a connection come up, and how long it took;
 * * `<mode>:ping` – the delay of the server in use when a session ended;
 * * `<mode>:stable` – for a session of at least [STABLE_AFTER_MS], whether it
 *   ran without the server being replaced.
 *
 * The mode is one of four fixed names and the metric one of three; no server,
 * name, address or time of day goes with them, and delays are rounded before
 * they leave the phone like every other crowd figure. The maintainers read
 * only totals over many people, sealed so that only they can (see
 * `deploy/crowd-relay/README.md`).
 */
object ModeStats {
    /** A session shorter than this says nothing about stability. */
    const val STABLE_AFTER_MS = 5 * 60_000L

    /** Facts kept while there is no way to send them. */
    const val MAX_PENDING = 24

    private const val PREFS = "mode-stats"
    private const val KEY = "pending"

    fun mode(profile: ConnectionProfile): String = profile.name.lowercase()

    fun id(profile: ConnectionProfile, metric: String) = "${mode(profile)}:$metric"

    /** One fact: the id, whether it went well, and a delay in ms where that means something. */
    data class Fact(val id: String, val ok: Boolean, val ms: Int?)

    /** Whether a finished session counts as stable: long enough, and never had to change server. */
    fun stableSession(durationMs: Long, replacements: Int): Boolean? =
        if (durationMs < STABLE_AFTER_MS) null else replacements == 0

    fun record(context: Context, fact: Fact) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val list = read(prefs.getString(KEY, null))
        list.add(fact)
        while (list.size > MAX_PENDING) list.removeAt(0)
        prefs.edit().putString(KEY, write(list).toString()).apply()
    }

    /** What waits to be sent, as the crowd report carries it. */
    fun pending(context: Context): JSONArray = write(read(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null)))

    /** Drop the first [count] facts once they have been sent; ones recorded since stay. */
    fun sent(context: Context, count: Int) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val list = read(prefs.getString(KEY, null))
        repeat(minOf(count, list.size)) { list.removeAt(0) }
        prefs.edit().putString(KEY, write(list).toString()).apply()
    }

    /** Forget everything, for "clear history". */
    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY).apply()
    }

    internal fun read(text: String?): MutableList<Fact> {
        val out = ArrayList<Fact>()
        val arr = runCatching { JSONArray(text ?: "[]") }.getOrDefault(JSONArray())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out += Fact(o.optString("id"), o.optBoolean("ok"), if (o.has("ms")) o.optInt("ms") else null)
        }
        return out
    }

    internal fun write(list: List<Fact>): JSONArray = JSONArray().also { a ->
        list.forEach { f ->
            a.put(JSONObject().put("id", f.id).put("ok", f.ok).also { o -> f.ms?.let { o.put("ms", Crowd.bucketMs(it)) } })
        }
    }
}
