package com.zeronet.mobile.service

import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.DiscoveryProgress
import com.zeronet.mobile.model.DiscoveryStage
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.ImportResult
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.TrafficStats
import org.json.JSONArray
import org.json.JSONObject

/**
 * Message codes and codecs for the UI ⇄ :vpn Messenger channel.
 *
 * Everything crosses as a small JSON string in the message Bundle under
 * [KEY]. State is pushed on change, stats at most once a second and only
 * while a client is registered, so an idle or backgrounded UI costs nothing.
 */
object Ipc {
    const val KEY = "j"

    // UI → engine
    const val REGISTER = 1
    const val UNREGISTER = 2
    const val CONNECT = 3
    const val DISCONNECT = 4
    const val TEST = 5
    const val IMPORT = 6
    const val SCAN_START = 7
    const val SCAN_STOP = 8
    const val REFRESH = 9
    const val SETTINGS = 10
    const val ADD_SUBSCRIPTION = 11
    const val REMOVE_SUBSCRIPTION = 12

    // engine → UI
    const val STATE = 101
    const val STATS = 102
    const val SCAN = 103
    const val SERVERS_CHANGED = 104
    const val IMPORT_RESULT = 105
    const val TEST_PROGRESS = 106
    const val REFRESH_STATE = 107

    // ---------------------------------------------------------------- server

    fun serverToJson(s: Server): JSONObject = JSONObject()
        .put("key", s.key).put("link", s.link).put("name", s.name).put("protocol", s.protocol)
        .put("transport", s.transport).put("security", s.security).put("host", s.host).put("port", s.port)
        .put("country", s.country).put("source", s.source).put("favorite", s.favorite).put("delay", s.delayMs)

    fun serverFromJson(o: JSONObject): Server = Server(
        key = o.optString("key"), link = o.optString("link"), name = o.optString("name"),
        protocol = o.optString("protocol"), transport = o.optString("transport"), security = o.optString("security"),
        host = o.optString("host"), port = o.optInt("port"), country = o.optString("country"),
        source = o.optString("source"), favorite = o.optBoolean("favorite"), delayMs = o.optInt("delay", -1),
    )

    // ----------------------------------------------------------------- state

    fun stateToJson(state: ConnState): String {
        val o = JSONObject()
        when (state) {
            ConnState.Idle -> o.put("t", "idle")
            ConnState.Disconnecting -> o.put("t", "disconnecting")
            is ConnState.Searching -> o.put("t", "searching").put("p", progressToJson(state.progress))
            is ConnState.Connecting -> o.put("t", "connecting").apply { state.server?.let { put("s", serverToJson(it)) } }
            is ConnState.Connected -> o.put("t", "connected").put("s", serverToJson(state.server))
                .put("since", state.since).put("delay", state.delayMs).put("pool", state.pool)
            is ConnState.Reconnecting -> o.put("t", "reconnecting").put("reason", state.reason)
            is ConnState.Failed -> o.put("t", "failed").put("reason", state.reason.name).put("detail", state.detail)
        }
        return o.toString()
    }

    fun stateFromJson(text: String): ConnState {
        val o = JSONObject(text)
        return when (o.optString("t")) {
            "searching" -> ConnState.Searching(progressFromJson(o.optJSONObject("p") ?: JSONObject()))
            "connecting" -> ConnState.Connecting(o.optJSONObject("s")?.let(::serverFromJson))
            "connected" -> ConnState.Connected(
                serverFromJson(o.getJSONObject("s")), o.optLong("since"), o.optInt("delay", -1), o.optInt("pool", 1),
            )
            "reconnecting" -> ConnState.Reconnecting(o.optString("reason"))
            "failed" -> ConnState.Failed(
                FailReason.entries.firstOrNull { it.name == o.optString("reason") } ?: FailReason.CoreError,
                o.optString("detail"),
            )
            "disconnecting" -> ConnState.Disconnecting
            else -> ConnState.Idle
        }
    }

    fun progressToJson(p: DiscoveryProgress): JSONObject = JSONObject()
        .put("stage", p.stage.name).put("c", p.candidates).put("td", p.tcpDone).put("to", p.tcpOpen)
        .put("rd", p.realDone).put("a", p.alive)

    fun progressFromJson(o: JSONObject): DiscoveryProgress = DiscoveryProgress(
        stage = DiscoveryStage.entries.firstOrNull { it.name == o.optString("stage") } ?: DiscoveryStage.History,
        candidates = o.optInt("c"), tcpDone = o.optInt("td"), tcpOpen = o.optInt("to"),
        realDone = o.optInt("rd"), alive = o.optInt("a"),
    )

    // ----------------------------------------------------------------- stats

    fun statsToJson(s: TrafficStats): String = JSONObject()
        .put("ur", s.upRate).put("dr", s.downRate).put("ut", s.upTotal).put("dt", s.downTotal)
        .put("dh", JSONArray(s.downHistory)).put("uh", JSONArray(s.upHistory))
        .toString()

    fun statsFromJson(text: String): TrafficStats {
        val o = JSONObject(text)
        return TrafficStats(
            upRate = o.optLong("ur"), downRate = o.optLong("dr"), upTotal = o.optLong("ut"), downTotal = o.optLong("dt"),
            downHistory = o.optJSONArray("dh").longs(), upHistory = o.optJSONArray("uh").longs(),
        )
    }

    // ------------------------------------------------------------------ scan

    fun scanToJson(s: ScanState): String = JSONObject()
        .put("run", s.running).put("sc", s.scanned).put("re", s.responsive).put("to", s.total)
        .put("err", s.error ?: JSONObject.NULL)
        .put("r", JSONArray().also { a -> s.results.forEach { a.put(JSONObject().put("ip", it.ip).put("p", it.port).put("rtt", it.rttMs)) } })
        .toString()

    fun scanFromJson(text: String): ScanState {
        val o = JSONObject(text)
        val arr = o.optJSONArray("r") ?: JSONArray()
        return ScanState(
            running = o.optBoolean("run"), scanned = o.optInt("sc"), responsive = o.optInt("re"), total = o.optInt("to"),
            error = if (o.isNull("err")) null else o.optString("err"),
            results = List(arr.length()) { i -> arr.getJSONObject(i).let { ScanResult(it.optString("ip"), it.optInt("p"), it.optInt("rtt")) } },
        )
    }

    // ---------------------------------------------------------------- import

    fun importToJson(r: ImportResult): String = JSONObject()
        .put("a", r.added).put("d", r.duplicates).put("r", r.rejected).put("e", r.error ?: JSONObject.NULL).toString()

    fun importFromJson(text: String): ImportResult {
        val o = JSONObject(text)
        return ImportResult(o.optInt("a"), o.optInt("d"), o.optInt("r"), if (o.isNull("e")) null else o.optString("e"))
    }

    private fun JSONArray?.longs(): List<Long> = if (this == null) emptyList() else List(length()) { optLong(it) }
}
