package com.zeronet.mobile.service

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.telephony.TelephonyManager
import android.util.Log
import com.zeronet.mobile.core.ZrayNative
import com.zeronet.mobile.data.NetworkIdentity
import com.zeronet.mobile.data.ServerStore
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.model.Diagnosis
import com.zeronet.mobile.model.ServerKind
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.model.DiscoveryProgress
import com.zeronet.mobile.model.DiscoveryStage
import com.zeronet.mobile.model.EvasionLevel
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.ImportResult
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.model.SpeedFloor
import com.zeronet.mobile.model.TrafficStats
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Hosts the tunnel: implemented by [ZeroVpnService]. The engine decides
 * *when* to bring the interface up; the service owns the platform objects.
 */
interface TunnelHost {
    /** Establish the VPN interface; null when permission is missing or revoked. */
    fun establish(settings: Settings): ParcelFileDescriptor?
    fun onStateChanged(state: ConnState)
    fun onStats(stats: TrafficStats)
    fun finish()
}

/**
 * The connection engine: one per :vpn process.
 *
 * Connect is a race, not a ranking (PLAN.md §4): test this network's past
 * winners, then stream discovery, and bring the tunnel up on the *first*
 * config that really carries traffic. Discovery keeps going in the
 * background; every further working config is added to Zray's balancer with
 * a hot reload that never tears the interface down.
 */
object Engine {
    private const val TAG = "ZeroEngine"
    private const val WANT_ALIVE = 5
    /** Connected with this many servers (the one in use plus backups): stop searching. */
    private const val STOP_DISCOVERY_AT = 3
    /**
     * A search that runs with the tunnel up stops at this many servers, or
     * after [BACKGROUND_SEARCH_MS], whichever comes first. Without a bound it
     * kept going through thousands of candidates whenever suitable servers
     * were scarce (Normal mode, which wants TLS/REALITY only, found two and
     * then scanned 8,000 more looking for a third).
     */
    private const val BACKGROUND_WANT = 2
    private const val BACKGROUND_SEARCH_MS = 20_000L
    private const val PROFILE_SETTLE_MS = 600L
    /** [ConnState.Reconnecting] reason: the config the user chose stopped answering; retrying it. */
    const val REASON_CHOSEN_DOWN = "chosen_down"
    /** [ConnState.Reconnecting] reason: nothing works yet; the kill switch blocks traffic while the engine retries. */
    const val REASON_BLOCKED = "blocked"
    /** With the kill switch on, a failed connect is retried this often (or on a network change). */
    private const val KILL_SWITCH_RETRY_MS = 30_000L

    // ------------------------------------------------------------ profiles
    //
    // Three ways to connect, each shaped by what breaks in Iran:
    //
    // Normal — encrypted servers only (TLS or REALITY: the handshake looks
    //   like ordinary HTTPS and the payload is encrypted end to end), a pool
    //   of backups behind a balancer, anti-censorship as set, QUIC blocked so
    //   everything rides the disguised TCP path. The safe default.
    //
    // Fast — the first server that works, nothing more. History for this
    //   network is tried first, so it is usually instant; any protocol goes,
    //   no ClientHello fragmentation (it costs round trips), no backups, no
    //   background search. The health check still replaces a dead server.
    //
    // Gaming — online games need low ping, UDP and a path that never changes
    //   mid-match (a server switch drops the game session). So: lowest
    //   measured delay wins; CDN-fronted configs are skipped (the CDN hop adds
    //   latency and most cannot carry UDP); QUIC/UDP 443 is allowed; no
    //   fragmentation; exactly one server, swapped only if it dies. Iranian
    //   destinations (including domestic game servers) still go direct.

    private fun wantAlive(p: ConnectionProfile) = when (p) {
        ConnectionProfile.Normal -> WANT_ALIVE
        ConnectionProfile.Fast -> 1
        ConnectionProfile.Gaming -> 3
    }

    private fun stopDiscoveryAt(p: ConnectionProfile) = when (p) {
        ConnectionProfile.Normal -> STOP_DISCOVERY_AT
        ConnectionProfile.Fast -> 1
        ConnectionProfile.Gaming -> 2
    }

    /** How many pool members go into the config: the rest are standby for the health check. */
    private fun linksInConfig(p: ConnectionProfile) = when (p) {
        ConnectionProfile.Normal -> WANT_ALIVE
        ConnectionProfile.Fast, ConnectionProfile.Gaming -> 1
    }

    /** Whether a discovered or stored server suits the profile. A server the user picked always does. */
    private fun suits(server: Server, p: ConnectionProfile): Boolean {
        if (excludedByCountry(server)) return false
        return when (p) {
            ConnectionProfile.Normal -> server.security == "tls" || server.security == "reality" ||
                server.protocol == "hysteria2" || server.protocol == "tuic"
            ConnectionProfile.Fast -> true
            ConnectionProfile.Gaming -> server.kind != com.zeronet.mobile.model.ServerKind.Cdn &&
                server.transport !in setOf("ws", "httpupgrade", "xhttp", "splithttp")
        }
    }

    /**
     * A server in the user's own country is excluded from automatic selection:
     * tunnelling from a censored country to itself bypasses nothing and leaks
     * the real location. Excluded only for the automatic [ConnectTarget.Fastest]
     * path; picking that country (or a specific server / subscription) always
     * connects. Servers with an unknown country ("") are never excluded.
     */
    private fun excludedByCountry(server: Server): Boolean {
        if (target !is ConnectTarget.Fastest) return false
        val home = homeCountry
        return home.isNotEmpty() && server.country == home
    }

    /** The cellular network's country (ISO alpha-2, upper case), or "" on Wi-Fi / unknown. */
    private fun detectHomeCountry(): String {
        val tm = app.getSystemService(TelephonyManager::class.java) ?: return ""
        val raw = runCatching { tm.networkCountryIso }.getOrNull()?.takeIf { it.isNotBlank() }
            ?: runCatching { tm.simCountryIso }.getOrNull()
        val code = raw?.trim()?.uppercase(Locale.ROOT).orEmpty()
        return if (code.length == 2) code else ""
    }
    private const val HEALTH_INTERVAL_MS = 45_000L
    /** When every server fails a health check, test again this much later before believing it. */
    private const val HEALTH_RETEST_MS = 3_000L
    /** Failed health checks in a row before a chosen config is reported as not answering. */
    private const val CHOSEN_DOWN_AFTER = 2
    /** Test timeout for the user's own configs; see [testServers]. */
    private const val OWN_TIMEOUT_MS = 10_000
    /** Servers other users reported working on this network, tested before searching. */
    private const val CROWD_PICKS = 12
    /** How long a connect waits for the crowd rankings when it has none on disk. */
    private const val CROWD_FETCH_MS = 3_000
    /** Not Cloudflare: Worker-served configs (BPB and the like) cannot reach Cloudflare addresses. */
    private const val PROBE_URL = "http://www.gstatic.com/generate_204"

    // ---- speed-based switching -------------------------------------------------
    /** Seconds of real traffic the slow decision looks at. */
    private const val SPEED_WINDOW = 20
    /** A one-second sample below this is not the user transferring anything. */
    private const val MIN_ACTIVE_BPS = 4_000L
    /** At least this many of the window's samples must be active to judge speed. */
    private const val ACTIVE_SAMPLES = 6
    /** Silence this long, with connections still open, counts as a stall. */
    private const val STALL_AFTER_MS = 15_000L
    /** Past this, the silence is ordinary idleness, not a stalled download. */
    private const val STALL_GIVEUP_MS = 45_000L
    /** A server switched away from for being slow is not used again until this passes. */
    private const val SLOW_COOLDOWN_MS = 10 * 60_000L
    /** Saved servers per family the self-test tries. */
    private const val FAMILY_SAMPLE = 4

    private lateinit var app: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val mutex = Mutex()

    val state = MutableStateFlow<ConnState>(ConnState.Idle)
    val stats = MutableStateFlow(TrafficStats())
    val scan = MutableStateFlow(ScanState())
    val refreshing = MutableStateFlow(false)
    val testProgress = MutableStateFlow<Pair<Int, Int>?>(null)
    val serversChanged = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /** Number of UI clients currently registered; stats are only computed when > 0 or the screen is on. */
    val clients = AtomicInteger(0)

    @Volatile var nativeError: String? = null
        private set

    private var host: TunnelHost? = null
    private var connectJob: Job? = null
    private var refreshJob: Job? = null
    private var testJob: Job? = null
    /** The pending reaction to a profile change; a newer change replaces it. */
    private var profileJob: Job? = null
    private var scanJob: Job? = null
    private var monitorJob: Job? = null
    /** Health checks in a row in which the chosen config failed; see [CHOSEN_DOWN_AFTER]. */
    private var chosenFailures = 0
    private val healthNow = Channel<Unit>(Channel.CONFLATED)
    /** Wakes the kill-switch retry loop early (a network change). */
    private val retryNow = Channel<Unit>(Channel.CONFLATED)

    /**
     * The kill switch's placeholder interface: an established VPN interface
     * nobody reads. While it is the live interface every app's packets go
     * into it and nowhere else, so nothing leaks while no server carries
     * traffic. Replaced (and then closed) as soon as the real tunnel comes up.
     */
    private var blocker: ParcelFileDescriptor? = null
    /** The network the current connection started or last moved on; see [onNetworkChanged]. */
    @Volatile private var lastNetworkId: String? = null

    @Volatile private var settings = Settings()
    @Volatile private var target: ConnectTarget = ConnectTarget.Fastest
    @Volatile private var running = false

    /** Working configs currently behind the balancer, fastest first. */
    private val pool = ArrayList<Alive>()
    /**
     * Server keys excluded for being slow, until the given epoch-millisecond
     * time. Kept out of the config's link list so the balancer cannot pick
     * them again (least-ping would: it knows their latency, not their
     * throughput). A cooldown expired entry is simply ignored, so no sweep.
     */
    private val slowUntil = ConcurrentHashMap<String, Long>()
    /** Last time real traffic moved, for stall detection. */
    private var lastActiveAt = 0L
    /** Consecutive seconds a stall has lasted. */
    private var stallSeconds = 0
    /** Last time a server was dropped for being slow, so decisions don't flap. */
    private var lastSlowSwitchAt = 0L
    /**
     * The user's own country (ISO-3166 alpha-2, upper case) from the cellular
     * network, or "" when unknown / on Wi-Fi. Cached per connection run and per
     * network change. Automatic discovery skips servers in this country: a
     * tunnel from a censored country to itself bypasses nothing and exposes the
     * user's real location. An explicit country choice is honoured regardless.
     */
    @Volatile private var homeCountry: String = ""
    /** Test results for public servers during this connect, for [reportCrowd]. */
    private val crowdResults = LinkedHashMap<String, Crowd.Result>()
    /** Clean Cloudflare addresses others found on this network, used after the user's own scan results. */
    @Volatile private var crowdCleanIps: List<String> = emptyList()
    private var since = 0L

    private data class Alive(val server: Server, val delayMs: Int)

    /** Thrown inside a discovery/test collector to stop it after bring-up failed (state is already Failed). */
    private class BringUpFailed : Exception() {
        override fun fillInStackTrace(): Throwable = this
    }

    private val store: ServerStore get() = ServerStore.get(app)

    // ------------------------------------------------------------------ setup

    fun init(context: Context) {
        app = context.applicationContext
        EngineLog.init(app)
        settings = readOptions() ?: settings
        nativeError = runCatching { ZrayNative.init(app.filesDir.absolutePath, coreLogLevel(settings)) }
            .fold({ it }, { "native library failed to load: ${it.message}" })
        if (nativeError != null) EngineLog.e("native init: $nativeError")
    }

    /** Warnings are always kept for the Diagnostics screen; "detailed logs" adds the core's info lines. */
    private fun coreLogLevel(s: Settings) = if (s.logs) "info" else "warn"

    // ------------------------------------------------------------- connecting

    /** Remember what to connect to; [ZeroVpnService] calls [start] once it is in the foreground. */
    fun prepare(target: ConnectTarget, settings: Settings) {
        this.target = target
        this.settings = settings
    }

    /** Called by the service when it has started (user connect, always-on, tile or boot). */
    fun start(host: TunnelHost, fromSystem: Boolean) {
        this.host = host
        if (fromSystem) {
            settings = readOptions() ?: settings
            target = ConnectTarget.decode(settings.lastTarget)
        }
        refreshJob?.cancel()
        connectJob?.cancel()
        monitorJob?.cancel()
        connectJob = scope.launch {
            mutex.withLock { runConnection() }
            afterConnectAttempt()
        }
    }

    /**
     * After a connect attempt: with the kill switch holding traffic, a
     * failure that may pass (nothing answered, no network) is retried rather
     * than ending the connection, so the phone stays blocked instead of
     * leaking. Otherwise a failed attempt must not leave a foreground service
     * and its notification behind; the UI shows the failure.
     */
    private suspend fun afterConnectAttempt() {
        while (!running && blocker != null && currentCoroutineContext().isActive) {
            val failed = state.value as? ConnState.Failed ?: break
            if (failed.reason !in RETRYABLE) break
            publish(ConnState.Reconnecting(REASON_BLOCKED))
            EngineLog.i("kill switch: ${failed.reason} — traffic stays blocked; trying again in ${KILL_SWITCH_RETRY_MS / 1000} s")
            retryNow.tryReceive()
            withTimeoutOrNull(KILL_SWITCH_RETRY_MS) { retryNow.receive() }
            mutex.withLock { runConnection() }
        }
        if (!running && state.value is ConnState.Failed) {
            releaseBlocker()
            this@Engine.host?.finish()
            this@Engine.host = null
        }
    }

    private val RETRYABLE = setOf(FailReason.NoWorkingServer, FailReason.NoNetwork, FailReason.ServerUnavailable)

    /** Put the kill switch's placeholder interface in place, if the user wants one and none is up. */
    private fun holdBlocker() {
        if (!settings.killSwitch || settings.mode != ConnectionMode.Vpn || blocker != null) return
        blocker = host?.establish(settings)
        if (blocker != null) EngineLog.i("kill switch: blocking traffic until a server answers")
    }

    /** Close the placeholder: after the real interface replaced it, or when the user disconnects. */
    private fun releaseBlocker() {
        blocker?.let { runCatching { it.close() } }
        blocker = null
    }

    fun disconnect() {
        connectJob?.cancel()
        monitorJob?.cancel()
        scope.launch {
            mutex.withLock {
                publish(ConnState.Disconnecting)
                teardown()
                releaseBlocker()
                EngineLog.i("disconnected")
                publish(ConnState.Idle)
            }
            host?.finish()
            host = null
        }
    }

    /**
     * User asked to move off the current server (the notification button).
     * Same path as an automatic slow/stall switch, but ignores the speed
     * floor and cooldown so a manual tap always acts when there is somewhere
     * to go. Does nothing with a single server or a config the user chose.
     */
    fun switchServer() {
        if (!running) return
        scope.launch { dropPrimary("manual", force = true) }
    }

    /** Another VPN took over, or the user revoked the permission in system settings. */
    fun onRevoked() {
        connectJob?.cancel()
        monitorJob?.cancel()
        scope.launch {
            mutex.withLock {
                teardown()
                releaseBlocker()
                EngineLog.w("VPN permission revoked or another VPN took over")
                publish(ConnState.Failed(FailReason.VpnRevoked, ""))
            }
            host?.finish()
            host = null
        }
    }

    /** The default network changed (Wi-Fi ↔ cellular, reconnect). */
    fun onNetworkChanged() {
        val id = NetworkIdentity.current(app)
        val moved = id != null && id != lastNetworkId
        if (id != null) lastNetworkId = id
        // Joined a network the user trusts: ZeroNet is not needed here. Only
        // on a move, so connecting by hand on a trusted network still works.
        if (moved && settings.trusts(id) && state.value.isActive) {
            EngineLog.i("joined trusted network ${settings.trustedLabel(id)}: disconnecting")
            disconnect()
            return
        }
        if (moved) EngineLog.i("network changed (${NetworkIdentity.label(app).ifBlank { "unknown" }})")
        // Blocked and waiting for a retry: a new network is worth trying at once.
        if (!running && blocker != null) retryNow.trySend(Unit)
        if (!running) return
        homeCountry = detectHomeCountry()
        runCatching { ZrayNative.networkChanged() }
        // Checked inside the monitor loop so a disconnect cancels it with the loop.
        healthNow.trySend(Unit)
    }

    /** Settings changed in the UI; apply what can be applied live. */
    fun applySettings(next: Settings) {
        val previous = settings
        settings = next
        if (previous.logs != next.logs && nativeError == null) {
            runCatching { ZrayNative.setLogLevel(coreLogLevel(next)) }
            EngineLog.i("detailed core logs ${if (next.logs) "on" else "off"}")
        }
        // Turned off while blocked and waiting: stop blocking.
        if (previous.killSwitch && !next.killSwitch && !running && blocker != null) {
            releaseBlocker()
            retryNow.trySend(Unit)
        }
        // Still searching: start over, so the search itself follows the new mode.
        if (!running && previous.profile != next.profile && connectJob?.isActive == true) {
            profileJob?.cancel()
            profileJob = scope.launch {
                delay(PROFILE_SETTLE_MS)
                reconnect()
            }
            return
        }
        if (!running) return
        when {
            // Zray's hot reload keeps the inbound set fixed, so listener
            // changes (LAN sharing, credentials, ports) need a quick restart.
            topology(previous) != topology(next) -> scope.launch { mutex.withLock { restartCore() } }
            previous.profile != next.profile -> {
                // A mode is more than a few settings: it decides which servers
                // qualify and how many, so switching reconnects from scratch.
                // Tapping through the modes quickly: only the last choice
                // counts, once the taps have settled.
                profileJob?.cancel()
                profileJob = scope.launch {
                    delay(PROFILE_SETTLE_MS)
                    reconnect()
                }
            }
            routing(previous) != routing(next) -> scope.launch { mutex.withLock { reloadPool() } }
        }
    }

    /**
     * Drop the current connection and connect again to the same target with
     * the current settings. The foreground service and its notification stay
     * up throughout; in VPN mode the new interface replaces the old one.
     */
    private fun reconnect() {
        refreshJob?.cancel()
        connectJob?.cancel()
        monitorJob?.cancel()
        connectJob = scope.launch {
            mutex.withLock {
                withContext(NonCancellable) {
                    // Blocked before the old tunnel goes, so nothing slips out in between.
                    holdBlocker()
                    teardown()
                }
                runConnection()
            }
            afterConnectAttempt()
        }
    }

    /**
     * Look for working servers with the tunnel up. With a subscription chosen
     * only its own configs are candidates; anything else searches the feeds.
     */
    private suspend fun findReplacements(network: String, excludeKeys: Set<String>) {
        when (val t = target) {
            is ConnectTarget.Subscription -> {
                val all = withContext(Dispatchers.IO) { store.inSubscription(t.id) }
                testAndCollect(all.filter { it.key !in excludeKeys }.ifEmpty { all }, network)
            }
            else -> discover(network, excludeKeys)
        }
    }

    private fun topology(s: Settings) = listOf(s.lanShare, s.lanUser, s.lanPass, s.socksPort, s.httpPort)

    private fun routing(s: Settings) = listOf(
        s.iranDirect, s.blockQuic, s.evasion, s.remoteDns, s.customDns, s.blockAds, s.logs,
    )

    /**
     * Stop and start the core with the current pool. In VPN mode a fresh
     * interface is established; Android swaps it in for the old one, so the
     * system VPN stays up across the restart.
     */
    private suspend fun restartCore() {
        if (!running || pool.isEmpty()) return
        val up = withContext(NonCancellable) {
            holdBlocker()
            EngineLog.i("restarting the core")
            ZrayNative.stop()?.let { EngineLog.w("restart stop: $it") }
            running = false
            val keepSince = since
            bringUpAtomically().also { if (it) since = keepSince }
        }
        if (!up) {
            // The failure is already published; a core that will not start
            // is not something retrying fixes, so stop blocking and end.
            monitorJob?.cancel()
            releaseBlocker()
            host?.finish()
            host = null
            return
        }
        publishConnected()
    }

    private suspend fun runConnection() {
        pool.clear()
        crowdResults.clear()
        chosenFailures = 0
        slowUntil.clear()
        stallSeconds = 0
        lastActiveAt = System.currentTimeMillis()
        lastSlowSwitchAt = 0L
        homeCountry = detectHomeCountry()
        publish(ConnState.Searching(DiscoveryProgress()))
        holdBlocker()
        if (nativeError != null) {
            fail(FailReason.CoreError, nativeError.orEmpty()); return
        }
        val network = NetworkIdentity.current(app)
        if (network == null) {
            fail(FailReason.NoNetwork, ""); return
        }
        lastNetworkId = network
        EngineLog.i(
            "connect: ${target.encode()}, ${settings.profile} mode, ${settings.mode}" +
                ", on ${NetworkIdentity.label(app).ifBlank { "an unknown network" }}" +
                (if (homeCountry.isNotEmpty()) " ($homeCountry)" else "") +
                (if (blocker != null) ", kill switch holding" else ""),
        )
        try {
            when (val t = target) {
                is ConnectTarget.Specific -> {
                    val server = withContext(Dispatchers.IO) { store.byKey(t.key) }
                    if (server == null) { fail(FailReason.ServerUnavailable, ""); return }
                    publish(ConnState.Connecting(server))
                    pool += Alive(server, server.delayMs)
                    if (!bringUp()) return
                }
                is ConnectTarget.Country -> {
                    val candidates = withContext(Dispatchers.IO) { store.inCountry(t.code) }
                    if (candidates.isEmpty()) { fail(FailReason.ServerUnavailable, t.code); return }
                    testAndCollect(candidates, network)
                    if (!running) { fail(FailReason.NoWorkingServer, t.code); return }
                }
                is ConnectTarget.Subscription -> {
                    val candidates = withContext(Dispatchers.IO) { store.inSubscription(t.id) }
                    if (candidates.isEmpty()) { fail(FailReason.ServerUnavailable, ""); return }
                    testAndCollect(candidates, network)
                    if (!running) { fail(FailReason.NoWorkingServer, ""); return }
                }
                ConnectTarget.Fastest -> {
                    val tried = tryKnownFirst(network)
                    if (pool.size < stopDiscoveryAt(settings.profile)) discover(network, excludeKeys = tried)
                    if (!running) { reportCrowd(network); fail(FailReason.NoWorkingServer, ""); return }
                }
            }
            reportCrowd(network)
            monitorJob = scope.launch { monitor(network) }
        } catch (e: BringUpFailed) {
            // bringUp() already published the failure.
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            EngineLog.e("connection failed", e)
            teardown()
            fail(FailReason.CoreError, e.message.orEmpty())
        }
    }

    /**
     * Before searching: test, all at once, what worked on this network
     * before and what worked for other people on it (the crowd rankings),
     * and bring the tunnel up on the first that answers. Usually one of
     * them does, and the feeds need not be fetched at all. Returns the keys
     * tested, which the search then skips.
     */
    private suspend fun tryKnownFirst(network: String): Set<String> {
        val crowdName = Crowd.networkName(app, network)
        val rankings = withContext(Dispatchers.IO) { Crowd.rankings(app, null, CROWD_FETCH_MS) }
        val picks = rankings?.let { Crowd.picks(it, crowdName, CROWD_PICKS) }.orEmpty()
        crowdCleanIps = rankings?.let { Crowd.cleanIps(it, crowdName) }.orEmpty().map { "${it.ip}:443" }
        val history = withContext(Dispatchers.IO) { store.historyLinks(network, 12) }
        val links = (history + picks.map { it.link }).distinct()
        if (links.isEmpty()) return emptySet()

        val items = JSONObject(ZrayNative.parseLinks(links.joinToString("\n"))).optJSONArray("items") ?: JSONArray()
        val parsed = List(items.length()) { Server.fromLinkInfo(items.getJSONObject(it), Server.SOURCE_FEED_PREFIX + "crowd") }
        // A server already stored keeps its record: its source says whether it is the user's own.
        val stored = withContext(Dispatchers.IO) { store.byKeys(parsed.map { it.key }) }.associateBy { it.key }
        val candidates = parsed.map { stored[it.key] ?: it }.distinctBy { it.key }.filter { suits(it, settings.profile) }
        if (candidates.isEmpty()) return parsed.map { it.key }.toSet()
        val byKey = candidates.associateBy { it.key }
        EngineLog.i("trying ${candidates.size} known servers first: ${history.size} from this network's history, ${picks.size} from other users on $crowdName")

        testServers(candidates, timeoutMs = 4000, concurrency = candidates.size) { key, delay, error ->
            val server = byKey[key] ?: return@testServers
            noteCrowd(server, delay)
            withContext(Dispatchers.IO) {
                if (delay >= 0 && key !in stored) store.upsert(listOf(server.copy(delayMs = delay)))
                store.recordResult(key, delay, network, error)
            }
            if (delay < 0) return@testServers
            if (pool.none { it.server.key == key }) pool += Alive(server.copy(delayMs = delay), delay)
            pool.sortBy { it.delayMs }
            if (!running) {
                publish(ConnState.Connecting(server))
                if (!bringUp()) throw BringUpFailed()
            } else if (pool.size <= linksInConfig(settings.profile)) {
                reloadPool()
            }
        }
        serversChanged.tryEmit(Unit)
        return parsed.map { it.key }.toSet()
    }

    /** Remember a public server's test result for the crowd report. Never the user's own configs. */
    private fun noteCrowd(server: Server, delay: Int) {
        if (server.isUser) return
        crowdResults[server.key] = Crowd.Result(server.key, delay >= 0, delay.coerceAtLeast(0))
    }

    /**
     * Share this connect's results for public servers, anonymously, when the
     * user allows it. Successes first, as the relay takes a limited number.
     */
    private fun reportCrowd(network: String) {
        val results = crowdResults.values.sortedBy { !it.ok }
        crowdResults.clear()
        if (!settings.shareResults || results.isEmpty()) return
        val tunnel = tunnelProxy()
        scope.launch(Dispatchers.IO) { Crowd.report(app, network, results, emptyList(), tunnel) }
    }

    /** The local HTTP proxy into the tunnel, while it is up. */
    private fun tunnelProxy(): java.net.Proxy? =
        if (running) java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", settings.httpPort)) else null

    /** Stream discovery; bring the tunnel up on the first working config. */
    private suspend fun discover(network: String, excludeKeys: Set<String>) {
        val request = JSONObject()
            .put("sources", Sources.toJson(Sources.enabled(settings.disabledSources)))
            .put("cache_dir", File(app.cacheDir, "feeds").apply { mkdirs() }.absolutePath)
            .put("priority_links", JSONArray(withContext(Dispatchers.IO) { store.historyLinks(network, 12) }))
            .put("extra_links", JSONArray(withContext(Dispatchers.IO) { store.userServers().map { it.link } }))
            .put("exclude_keys", JSONArray(excludeKeys.toList()))
            .put("want_alive", wantAlive(settings.profile))
            .put("max_seconds", 75)
            .put("tcp_concurrency", 256).put("tcp_timeout_ms", 1500).put("tcp_stop_after_open", 1500)
            .put("real_concurrency", 64).put("real_timeout_ms", 3000)
            .put("probe_url", PROBE_URL)
            .put("next_tier_if_alive_below", 3)
            .put("fetch", true)
        var progress = DiscoveryProgress()
        var pendingReload = false
        var lastReload = 0L
        // Once the tunnel is up with a couple of backups, stop. Discovery runs
        // hundreds of probes in parallel; left going for up to 75 s after the
        // user is connected, it competed with their own traffic on exactly
        // the slow links it exists for (images in Telegram stalled).
        var enough = false
        // When the tunnel came up (or was already up): the clock for the
        // background part of the search.
        var upAt = if (running) System.currentTimeMillis() else 0L
        val target = if (running) BACKGROUND_WANT else stopDiscoveryAt(settings.profile)
        fun overtime() = upAt > 0L && pool.isNotEmpty() && System.currentTimeMillis() - upAt > BACKGROUND_SEARCH_MS
        nativeJob { ZrayNative.discover(request.toString(), it) }.takeWhile { !enough && !overtime() }.collect { e ->
            when (e.optString("t")) {
                "stage" -> {
                    progress = progress.copy(stage = stageOf(e.optString("stage")))
                    EngineLog.i("search: ${e.optString("stage")} stage")
                    if (!running) publish(ConnState.Searching(progress))
                }
                "progress" -> {
                    progress = progress.copy(
                        candidates = e.optInt("candidates"), tcpDone = e.optInt("tcp_done"), tcpOpen = e.optInt("tcp_open"),
                        realDone = e.optInt("real_done"), alive = e.optInt("alive"),
                    )
                    if (!running) publish(ConnState.Searching(progress))
                }
                "alive" -> {
                    val info = e.optJSONObject("info") ?: return@collect
                    val delay = e.optInt("delay_ms", -1)
                    val server = Server.fromLinkInfo(info, Server.SOURCE_FEED_PREFIX + "discovered").copy(delayMs = delay)
                    EngineLog.i("search found ${describe(server)} answering in $delay ms")
                    withContext(Dispatchers.IO) {
                        store.upsert(listOf(server))
                        store.recordResult(server.key, delay, network)
                    }
                    serversChanged.tryEmit(Unit)
                    noteCrowd(server, delay)
                    // Remembered either way; used only if it suits the profile.
                    if (!suits(server, settings.profile)) return@collect
                    // Feeds list one server under many links; balance across servers, not links.
                    if (pool.none { it.server.key == server.key || (it.server.host == server.host && it.server.port == server.port) }) {
                        pool += Alive(server, delay)
                    }
                    // Only before the tunnel is up. Afterwards a new find joins
                    // the end: re-sorting would make it the server every new
                    // connection uses, switching servers under the user's
                    // feet on the strength of one probe.
                    // Gaming is the exception: in the few seconds after connecting,
                    // before a match starts, the lowest ping is worth one switch.
                    if (!running || settings.profile == ConnectionProfile.Gaming) {
                        pool.sortBy { if (it.delayMs < 0) Int.MAX_VALUE else it.delayMs }
                    }
                    if (running && pool.size >= target) enough = true
                    if (!running) {
                        publish(ConnState.Connecting(server))
                        if (!bringUp()) throw BringUpFailed()
                        lastReload = System.currentTimeMillis()
                        upAt = lastReload
                    } else {
                        pendingReload = true
                        // Coalesce reloads: at most one every 2 s while results stream in.
                        if (System.currentTimeMillis() - lastReload > 2_000) {
                            reloadPool(); pendingReload = false; lastReload = System.currentTimeMillis()
                        }
                    }
                }
                "error" -> EngineLog.w("search: ${e.optString("message")}")
                "done" -> {
                    EngineLog.i("search finished: ${progress.candidates} candidates, ${progress.tcpOpen} reachable, ${progress.alive} working")
                    if (pendingReload && running) { reloadPool(); pendingReload = false }
                }
            }
        }
        if (pendingReload && running) reloadPool()
        withContext(Dispatchers.IO) { store.prune() }
    }

    /**
     * Test [servers] through the core, one [onResult] per server.
     *
     * The user's own configs (imported or from their subscriptions) are tested
     * first, with a longer timeout and without the TLS confirmation. That
     * confirmation exists to weed out public-feed servers that answer the
     * plain probe without really relaying; for a config the user chose, its
     * second connection only adds a way to fail on a slow link, and a working
     * REALITY config showed no ping at all.
     */
    private suspend fun testServers(
        servers: List<Server>,
        timeoutMs: Int,
        concurrency: Int,
        onResult: suspend (key: String, delay: Int, error: String?) -> Unit,
    ) {
        val (own, feed) = servers.partition { it.isUser }
        for ((group, lenient) in listOf(own to true, feed to false)) {
            if (group.isEmpty()) continue
            val request = JSONObject()
                .put("links", JSONArray(group.map { it.link }))
                .put("concurrency", concurrency.coerceIn(1, group.size))
                .put("timeout_ms", if (lenient) maxOf(timeoutMs, OWN_TIMEOUT_MS) else timeoutMs)
                .put("probe_url", PROBE_URL)
            if (lenient) request.put("confirm_tls", false)
            var ok = 0
            val failures = HashMap<String, Int>()
            nativeJob { ZrayNative.testLinks(request.toString(), it) }.collect { e ->
                if (e.optString("t") != "result") return@collect
                val delay = e.optInt("delay_ms", -1)
                val error = e.optString("error").ifBlank { null }
                if (delay >= 0) ok++ else failures.merge(shortError(error), 1, Int::plus)
                onResult(e.optString("key"), delay, error)
            }
            val why = failures.entries.sortedByDescending { it.value }.take(5).joinToString { "${it.key} ×${it.value}" }
            EngineLog.i("tested ${group.size} ${if (lenient) "of your own" else "public"} servers: $ok working" + if (why.isNotEmpty()) "; failed: $why" else "")
        }
    }

    /** The gist of a core test error, so failures of one kind group together in the log. */
    private fun shortError(error: String?): String {
        val text = error?.lowercase(Locale.ROOT)?.trim().orEmpty()
        return when {
            text.isEmpty() -> "no answer"
            "timed out" in text || "timeout" in text || "deadline" in text -> "timeout"
            "reset" in text -> "connection reset"
            "refused" in text -> "connection refused"
            "certificate" in text || "handshake" in text || "tls" in text -> "TLS handshake"
            "dns" in text || "resolve" in text || "lookup" in text -> "DNS"
            "eof" in text || "closed" in text -> "closed early"
            else -> text.take(40)
        }
    }

    private fun describe(server: Server): String =
        "\"${server.name.take(40)}\" (${server.protocol}/${server.transport}/${server.security}${if (server.country.isNotEmpty()) ", " + server.country else ""})"

    /** Test stored candidates (country / refresh) and bring up on the first alive one. */
    private suspend fun testAndCollect(all: List<Server>, network: String) {
        // Prefer servers that suit the profile; if none of them do, any will.
        val candidates = all.filter { suits(it, settings.profile) }.ifEmpty { all }
        val byKey = candidates.associateBy { it.key }
        testServers(candidates.take(200), timeoutMs = 4000, concurrency = 16) { key, delay, error ->
            withContext(Dispatchers.IO) { store.recordResult(key, delay, network, error) }
            val server = byKey[key] ?: return@testServers
            if (delay < 0) return@testServers
            pool += Alive(server.copy(delayMs = delay), delay)
            pool.sortBy { it.delayMs }
            if (!running) {
                publish(ConnState.Connecting(server))
                if (!bringUp()) throw BringUpFailed()
            } else if (pool.size <= linksInConfig(settings.profile)) {
                reloadPool()
            }
        }
        serversChanged.tryEmit(Unit)
    }

    /** Build the config from the pool and start Zray (with the TUN in VPN mode). */
    private suspend fun bringUp(): Boolean = withContext(NonCancellable) { bringUpAtomically() }

    /**
     * Establish → hand over the descriptor → start, without a cancellation
     * point in between: a disconnect arriving half-way would otherwise orphan
     * the descriptor (handed over but never adopted) or leave the core running
     * while the engine believes it stopped. A disconnect waits for this to
     * finish and then tears down normally.
     */
    private suspend fun bringUpAtomically(): Boolean {
        val config = buildConfig() ?: return false
        var fd = -1
        if (settings.mode == ConnectionMode.Vpn) {
            val pfd = host?.establish(settings)
            if (pfd == null) {
                fail(FailReason.VpnPermission, ""); return false
            }
            fd = pfd.detachFd()
            ZrayNative.setTun(fd, settings.mtu)?.let { err ->
                closeFd(fd); fail(FailReason.CoreError, err); return false
            }
        }
        val err = withContext(Dispatchers.IO) { ZrayNative.start(config) }
        if (err != null) {
            if (fd >= 0) closeFd(fd)
            fail(FailReason.CoreError, err)
            return false
        }
        running = true
        since = System.currentTimeMillis()
        // The real interface replaced the placeholder; close its descriptor.
        releaseBlocker()
        usablePool().firstOrNull()?.let { EngineLog.i("tunnel up via ${describe(it.server)}, ${it.delayMs} ms, ${pool.size} in the pool") }
        publishConnected()
        return true
    }

    private suspend fun reloadPool() {
        if (!running || pool.isEmpty()) return
        val config = buildConfig(failOnError = false) ?: return
        val error = withContext(Dispatchers.IO) { ZrayNative.reload(config) }
        if (error != null) {
            EngineLog.w("reload refused, restarting: $error")
            restartCore()
            return
        }
        publishConnected()
    }

    private fun buildConfig(failOnError: Boolean = true): String? {
        val s = settings
        val links = usablePool().take(linksInConfig(s.profile))
        val request = JSONObject()
            .put("links", JSONArray(links.map { it.server.link }))
            .put("mode", if (s.mode == ConnectionMode.Vpn) "vpn" else "proxy")
            .put("tun", JSONObject().put("mtu", s.mtu).put("ipv6", s.ipv6))
            .put("socks_port", s.socksPort).put("http_port", s.httpPort)
            .put("lan", JSONObject().put("enabled", s.lanShare).put("listen", "0.0.0.0").put("user", s.lanUser).put("pass", s.lanPass))
            // Games and voice run over UDP: Gaming never blocks it.
            .put("iran_direct", s.iranDirect).put("block_ads", s.blockAds)
            .put("block_quic", s.blockQuic && s.profile != ConnectionProfile.Gaming)
            // Fragmenting the ClientHello costs round trips; Fast and Gaming skip it.
            .put("evasion", if (s.profile != ConnectionProfile.Normal) "off" else when (s.evasion) { EvasionLevel.Off -> "off"; EvasionLevel.Auto -> "auto"; EvasionLevel.Strong -> "strong" })
            .put("dns", JSONObject().put("remote", s.remoteDns.name.lowercase()).put("custom", s.customDns.trim()).put("local", "google").put("fakedns", s.fakeDns))
            // The user's own scan first, then what others found on this network.
            .put("clean_ips", JSONArray((scan.value.results.take(10).map { "${it.ip}:${it.port}" } + crowdCleanIps).distinct().take(20)))
            .put("log_level", if (s.logs) "info" else "warning")
        val result = JSONObject(ZrayNative.buildConfig(request.toString()))
        if (result.has("error")) {
            EngineLog.e("buildConfig: ${result.optString("error")}")
            if (failOnError) fail(FailReason.CoreError, result.optString("error"))
            return null
        }
        return result.getJSONObject("config").toString()
    }

    private fun publishConnected() {
        val best = usablePool().firstOrNull() ?: return
        publish(ConnState.Connected(best.server, since, best.delayMs, pool.size))
    }

    /**
     * The pool members that are not on a slow cooldown, in order. Falls back
     * to the whole pool when every member is cooling down, so a slow tunnel is
     * never traded for no tunnel.
     */
    private fun usablePool(now: Long = System.currentTimeMillis()): List<Alive> {
        val usable = pool.filter { (slowUntil[it.server.key] ?: 0L) <= now }
        return usable.ifEmpty { pool }
    }

    // ---------------------------------------------------------- health & stats

    private suspend fun monitor(network: String) {
        var lastUp = 0L
        var lastDown = 0L
        val downHistory = ArrayDeque<Long>(60)
        val upHistory = ArrayDeque<Long>(60)
        var tick = 0L
        lastActiveAt = System.currentTimeMillis()
        val power = app.getSystemService(PowerManager::class.java)
        while (currentCoroutineContext().isActive && running) {
            // Sleep one second, or less when a network change asks for a health check now.
            val forced = withTimeoutOrNull(1000) { healthNow.receive() } != null
            tick++
            val interactive = power?.isInteractive ?: true
            // The counters are cheap atomic reads; they are read even with the
            // screen off so a background download still feeds the slow/stall
            // decision. Only the notification is gated on the screen.
            val raw = ZrayNative.stats()
            if (raw != null) {
                val o = JSONObject(raw)
                val up = o.optLong("up")
                val down = o.optLong("down")
                val sessions = o.optInt("sessions", 0)
                val upRate = (up - lastUp).coerceAtLeast(0)
                val downRate = (down - lastDown).coerceAtLeast(0)
                lastUp = up; lastDown = down
                if (downHistory.size == 60) downHistory.removeFirst()
                if (upHistory.size == 60) upHistory.removeFirst()
                downHistory.addLast(downRate); upHistory.addLast(upRate)
                val next = TrafficStats(upRate, downRate, up, down, downHistory.toList(), upHistory.toList())
                stats.value = next
                if (interactive && tick % 2 == 0L) host?.onStats(next)
                maybeSwitchOnSpeed(downRate, upRate, sessions, downHistory)
            }
            if (forced || (settings.autoSwitch && tick * 1000 % HEALTH_INTERVAL_MS == 0L)) {
                healthCheck(NetworkIdentity.current(app) ?: network)
            }
        }
    }

    /**
     * Move to another server when the one in use is too slow or has stalled.
     *
     * Only real traffic is judged: a config is slow while the phone is moving
     * data, never while idle, so an untouched phone never triggers a switch.
     * A stall — bytes simply stopping while connections are open — is caught
     * separately because a fully stalled link moves no bytes at all and so
     * never trips the "slow" average. The current primary is then put on a
     * cooldown, which keeps the balancer from picking it straight back and
     * stops the choice flapping between two servers.
     *
     * Disabled in Gaming (a switch drops the game session) and when the user
     * picked a specific config. Runs under the engine mutex.
     */
    private suspend fun maybeSwitchOnSpeed(
        downRate: Long,
        upRate: Long,
        sessions: Int,
        downHistory: ArrayDeque<Long>,
    ) {
        if (!settings.autoSwitch || settings.profile == ConnectionProfile.Gaming) return
        if (target is ConnectTarget.Specific || !running || pool.size < 2) return
        val floor = settings.speedFloorBytes
        if (floor <= 0) return
        val now = System.currentTimeMillis()
        val moving = downRate + upRate > MIN_ACTIVE_BPS
        if (moving) lastActiveAt = now

        // Stall: connections are open, but nothing has moved for a while, and
        // the silence began while a real transfer was in progress.
        if (sessions > 0 && !moving) {
            val silent = now - lastActiveAt
            if (silent in STALL_AFTER_MS..STALL_GIVEUP_MS) {
                stallSeconds++
                // Silence this long means the stall started while a transfer
                // was running, not during ordinary idleness.
                if (stallSeconds >= (STALL_AFTER_MS / 1000).toInt() && now - lastSlowSwitchAt > SLOW_COOLDOWN_MS) {
                    stallSeconds = 0
                    dropPrimary("stalled")
                }
            } else {
                stallSeconds = 0
            }
            return
        }
        stallSeconds = 0

        // Slow: the whole window of real transfer stayed under the floor.
        if (downHistory.size < SPEED_WINDOW) return
        val window = downHistory.toList().takeLast(SPEED_WINDOW)
        val active = window.count { it > MIN_ACTIVE_BPS } >= ACTIVE_SAMPLES
        val peak = window.maxOrNull() ?: 0L
        val avg = window.sum() / window.size
        if (active && peak < floor && avg < floor && now - lastSlowSwitchAt > SLOW_COOLDOWN_MS) {
            dropPrimary("slow")
        }
    }

    /**
     * Put the primary server on a short cooldown and let the next one take
     * over. A reload excludes the cooled-down server from the config, which
     * is the only way to move off it: the balancer ranks by latency, not by
     * throughput, so a slow-but-low-ping server would otherwise be re-chosen.
     */
    private suspend fun dropPrimary(reason: String, force: Boolean = false) = mutex.withLock {
        if (!running || pool.size < 2) return@withLock
        if (settings.profile == ConnectionProfile.Gaming && !force) return@withLock
        if (target is ConnectTarget.Specific) return@withLock
        val now = System.currentTimeMillis()
        val primary = pool.first()
        slowUntil[primary.server.key] = now + SLOW_COOLDOWN_MS
        lastSlowSwitchAt = now
        // Put it at the back so the config's first link is a fresh server.
        pool.removeAt(0)
        pool.add(primary)
        val replacement = pool.firstOrNull { (slowUntil[it.server.key] ?: 0L) <= now }
        if (replacement == null) {
            // Everything is on cooldown; a slow tunnel beats no tunnel.
            slowUntil.clear()
            return@withLock
        }
        EngineLog.i("switching server ($reason): ${describe(primary.server)} -> ${describe(replacement.server)}")
        serversChanged.tryEmit(Unit)
        reloadPool()
        // Refill the pool in the background so the next switch has somewhere to go.
        val network = NetworkIdentity.current(app) ?: return@withLock
        scope.launch { runCatching { findReplacements(network, excludeKeys = pool.map { it.server.key }.toSet()) } }
    }

    private suspend fun healthCheck(network: String? = NetworkIdentity.current(app)) = mutex.withLock {
        if (!running) return@withLock
        val before = pool.map { it.server.key }
        if (pool.isNotEmpty()) {
            val results = HashMap<String, Int>()
            val errors = HashMap<String, String?>()
            suspend fun probe() = testServers(pool.map { it.server }, timeoutMs = 5000, concurrency = pool.size) { key, delay, error ->
                results[key] = delay
                errors[key] = error
            }
            probe()
            // One failed probe is weak evidence on these networks: a single
            // lost handshake would otherwise switch servers under the user,
            // or report a working config as dead. Test again before acting.
            if (results.values.none { it >= 0 }) {
                delay(HEALTH_RETEST_MS)
                if (!running) return@withLock
                probe()
            }
            withContext(Dispatchers.IO) { results.forEach { (k, d) -> store.recordResult(k, d, network, errors[k]) } }
            EngineLog.i("health check: ${results.values.count { it >= 0 }} of ${pool.size} servers answering")
            val survivors = pool.mapNotNull { a -> results[a.server.key]?.takeIf { it >= 0 }?.let { a.copy(delayMs = it) } }
                .sortedBy { it.delayMs }
                .toMutableList()
            // Keep the current primary unless it is clearly worse: a few
            // milliseconds between two probes is noise, and every change of
            // primary moves the user's new connections to another server.
            val primary = before.firstOrNull()?.let { key -> survivors.firstOrNull { it.server.key == key } }
            val best = survivors.firstOrNull()
            if (primary != null && best != null && primary !== best && primary.delayMs <= best.delayMs * 3 / 2 + 50) {
                survivors.remove(primary)
                survivors.add(0, primary)
            }
            // Servers on a slow cooldown go last (a stable sort keeps the
            // latency order inside each group), so the config's leading links
            // are the ones that can actually move data.
            val nowMs = System.currentTimeMillis()
            survivors.sortBy { if ((slowUntil[it.server.key] ?: 0L) > nowMs) 1 else 0 }
            serversChanged.tryEmit(Unit)
            // A config the user chose is never swapped for another: while it
            // is down, keep it in place and try it again on the next check.
            // Nothing depends on this verdict but the message, so it waits
            // for more than one failed check before saying so.
            if (target is ConnectTarget.Specific) {
                if (survivors.isEmpty()) {
                    chosenFailures++
                    if (chosenFailures >= CHOSEN_DOWN_AFTER) publish(ConnState.Reconnecting(REASON_CHOSEN_DOWN))
                } else {
                    chosenFailures = 0
                    pool.clear(); pool.addAll(survivors)
                    publishConnected()
                }
                return@withLock
            }
            pool.clear(); pool.addAll(survivors)
        }
        when {
            target is ConnectTarget.Specific -> publish(ConnState.Reconnecting(REASON_CHOSEN_DOWN))
            pool.isEmpty() -> {
                // Everything we had died (or an earlier search came back empty):
                // search again with the tunnel still up. Runs on every health
                // tick until something is found.
                publish(ConnState.Reconnecting("all servers stopped answering"))
                if (network != null) findReplacements(network, excludeKeys = before.toSet())
                if (pool.isEmpty()) publish(ConnState.Reconnecting("searching")) else reloadPool()
            }
            // Only the members that are in the config matter: a standby that
            // died or recovered needs no reload (and in Gaming a reload for
            // nothing is still a reload in the middle of a match).
            pool.take(linksInConfig(settings.profile)).map { it.server.key } !=
                before.take(linksInConfig(settings.profile)) -> reloadPool()
            else -> publishConnected()
        }
    }

    // -------------------------------------------------------------- self-test

    val diagnosis = MutableStateFlow(Diagnosis())
    private var diagJob: Job? = null

    /**
     * "Test my connection": what the phone's network does to plain traffic
     * (DNS poisoning, SNI filtering, block-page redirects), whether the
     * tunnel carries traffic, and which families of server get through right
     * now, tested with the servers already saved. Results stream into
     * [diagnosis] and the engine log.
     */
    fun diagnose() {
        if (diagJob?.isActive == true) return
        diagJob = scope.launch {
            val families = ServerKind.entries
            val ids = buildList {
                add(Diagnostics.NETWORK); add(Diagnostics.INTERNET); add(Diagnostics.DNS); add(Diagnostics.TLS)
                if (running) add(Diagnostics.TUNNEL)
                families.forEach { add(Diagnostics.FAMILY_PREFIX + it.name.lowercase(Locale.ROOT)) }
            }
            var checks = ids.map { DiagCheck(it, CheckStatus.Pending) }
            fun set(check: DiagCheck) {
                checks = checks.map { if (it.id == check.id) check else it }
                diagnosis.value = Diagnosis(running = true, checks = checks)
                if (check.status != CheckStatus.Running && check.status != CheckStatus.Pending) {
                    EngineLog.i("self-test ${check.id}: ${check.status}${if (check.detail.isNotEmpty()) " — ${check.detail}" else ""}")
                }
            }
            diagnosis.value = Diagnosis(running = true, checks = checks)
            EngineLog.i("self-test started")
            try {
                val network = NetworkIdentity.current(app)
                if (network == null) {
                    set(DiagCheck(Diagnostics.NETWORK, CheckStatus.Bad, "no network"))
                    ids.drop(1).forEach { set(DiagCheck(it, CheckStatus.Skipped)) }
                    return@launch
                }
                val label = NetworkIdentity.label(app).ifBlank { "unknown" }
                set(DiagCheck(Diagnostics.NETWORK, CheckStatus.Ok, if (homeCountry.isNotEmpty()) "$label ($homeCountry)" else label))
                val probes = listOf<Pair<String, () -> DiagCheck>>(
                    Diagnostics.INTERNET to Diagnostics::internet,
                    Diagnostics.DNS to Diagnostics::dns,
                    Diagnostics.TLS to Diagnostics::tls,
                )
                for ((id, probe) in probes) {
                    set(DiagCheck(id, CheckStatus.Running))
                    set(withContext(Dispatchers.IO) { probe() })
                }
                if (Diagnostics.TUNNEL in ids) {
                    set(DiagCheck(Diagnostics.TUNNEL, CheckStatus.Running))
                    set(if (running) withContext(Dispatchers.IO) { Diagnostics.tunnel(settings.httpPort) } else DiagCheck(Diagnostics.TUNNEL, CheckStatus.Skipped))
                }
                testFamilies(network, families) { set(it) }
            } finally {
                diagnosis.value = Diagnosis(running = false, checks = checks.map {
                    if (it.status == CheckStatus.Running || it.status == CheckStatus.Pending) it.copy(status = CheckStatus.Skipped) else it
                }, finishedAt = System.currentTimeMillis())
            }
        }
    }

    /**
     * Test a few saved servers of every family at once: the ones that worked
     * most recently, own configs included. A family with no saved servers is
     * skipped rather than reported as blocked.
     */
    private suspend fun testFamilies(network: String, families: List<ServerKind>, set: (DiagCheck) -> Unit) {
        fun id(kind: ServerKind) = Diagnostics.FAMILY_PREFIX + kind.name.lowercase(Locale.ROOT)
        val saved = withContext(Dispatchers.IO) { (store.userServers() + store.all()).distinctBy { it.key } }
        val picks = families.associateWith { kind ->
            saved.filter { it.kind == kind }
                .sortedWith(compareBy<Server> { if (it.delayMs >= 0) 0 else 1 }.thenByDescending { it.aliveCount - it.failCount })
                .take(FAMILY_SAMPLE)
        }
        picks.forEach { (kind, list) ->
            set(if (list.isEmpty()) DiagCheck(id(kind), CheckStatus.Skipped, "no saved servers of this kind") else DiagCheck(id(kind), CheckStatus.Running, "0 of ${list.size}"))
        }
        val all = picks.values.flatten()
        if (all.isEmpty()) return
        val kindOf = all.associate { it.key to it.kind }
        val done = HashMap<ServerKind, Int>()
        val ok = HashMap<ServerKind, MutableList<Int>>()
        testServers(all, timeoutMs = 5000, concurrency = all.size) { key, delay, error ->
            val kind = kindOf[key] ?: return@testServers
            withContext(Dispatchers.IO) { store.recordResult(key, delay, network, error) }
            done.merge(kind, 1, Int::plus)
            if (delay >= 0) ok.getOrPut(kind) { ArrayList() } += delay
            val total = picks[kind]?.size ?: 0
            val working = ok[kind].orEmpty()
            val finished = done[kind] == total
            val detail = "${working.size} of $total answered" + (working.minOrNull()?.let { ", best $it ms" } ?: "")
            set(
                DiagCheck(
                    id(kind),
                    when {
                        !finished -> CheckStatus.Running
                        working.isEmpty() -> CheckStatus.Bad
                        working.size * 2 < total -> CheckStatus.Warn
                        else -> CheckStatus.Ok
                    },
                    detail,
                ),
            )
        }
        serversChanged.tryEmit(Unit)
    }

    // ------------------------------------------------------------ servers tab

    /** Discovery without connecting: refills the server list. */
    fun refresh(next: Settings) {
        if (refreshJob?.isActive == true || connectJob?.isActive == true && !running) return
        settings = next
        refreshJob = scope.launch {
            refreshing.value = true
            try {
                val network = NetworkIdentity.current(app) ?: return@launch
                updateSubscriptions()
                val request = JSONObject()
                    .put("sources", Sources.toJson(Sources.enabled(next.disabledSources)))
                    .put("cache_dir", File(app.cacheDir, "feeds").apply { mkdirs() }.absolutePath)
                    .put("priority_links", JSONArray())
                    .put("extra_links", JSONArray())
                    .put("exclude_keys", JSONArray())
                    .put("want_alive", 20).put("max_seconds", 90)
                    .put("tcp_concurrency", 256).put("tcp_timeout_ms", 1500).put("tcp_stop_after_open", 1500)
                    .put("real_concurrency", 64).put("real_timeout_ms", 3000)
                    .put("probe_url", PROBE_URL).put("next_tier_if_alive_below", 10).put("fetch", true)
                nativeJob { ZrayNative.discover(request.toString(), it) }.collect { e ->
                    if (e.optString("t") != "alive") return@collect
                    val info = e.optJSONObject("info") ?: return@collect
                    val delay = e.optInt("delay_ms", -1)
                    val server = Server.fromLinkInfo(info, Server.SOURCE_FEED_PREFIX + "discovered")
                    withContext(Dispatchers.IO) {
                        store.upsert(listOf(server)); store.recordResult(server.key, delay, network)
                    }
                    serversChanged.tryEmit(Unit)
                }
                withContext(Dispatchers.IO) { store.prune() }
            } finally {
                refreshing.value = false
                serversChanged.tryEmit(Unit)
            }
        }
    }

    /** Real-delay test of stored servers (all when [keys] is empty). */
    fun test(keys: List<String>) {
        testJob?.cancel()
        testJob = scope.launch {
            // "Test all" is capped, and untested servers sort last, so the
            // user's own come first or they would never be reached.
            val servers = withContext(Dispatchers.IO) {
                if (keys.isEmpty()) (store.userServers() + store.all()).distinctBy { it.key } else store.byKeys(keys)
            }.take(400)
            if (servers.isEmpty()) return@launch
            val network = NetworkIdentity.current(app)
            var done = 0
            testProgress.value = 0 to servers.size
            var lastEmit = 0L
            try {
                testServers(servers, timeoutMs = 4000, concurrency = 16) { key, delay, error ->
                    withContext(Dispatchers.IO) { store.recordResult(key, delay, network, error) }
                    done++
                    testProgress.value = done to servers.size
                    val now = System.currentTimeMillis()
                    if (now - lastEmit > 500) { serversChanged.tryEmit(Unit); lastEmit = now }
                }
            } finally {
                testProgress.value = null
                serversChanged.tryEmit(Unit)
            }
        }
    }

    fun import(text: String): ImportResult {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return ImportResult(0, 0, 0, "empty")
        if ((trimmed.startsWith("https://") || trimmed.startsWith("http://")) && trimmed.lines().size == 1) {
            return addSubscription("", trimmed)
        }
        return importText(trimmed, Server.SOURCE_USER)
    }

    /**
     * A subscription URL may end in `#name`, the name the panel suggests
     * (BPB's `#💦 BPB Normal`). It names the subscription and is not part of
     * the address: browsers never send it, and two copies of one URL with
     * different names are the same subscription.
     */
    fun addSubscription(name: String, url: String): ImportResult {
        val address = url.trim().substringBefore('#')
        val suggested = url.trim().substringAfter('#', "").let { fragment ->
            runCatching { java.net.URLDecoder.decode(fragment.replace("+", "%2B"), "UTF-8") }.getOrDefault(fragment).trim()
        }
        val sub = Subscription(
            subscriptionId(address),
            name.ifBlank { suggested }.ifBlank { hostOf(address) },
            address, true, 0, 0,
        )
        store.upsertSubscription(sub)
        return fetchSubscription(sub)
    }

    fun removeSubscription(id: String) {
        store.deleteSubscription(id)
        serversChanged.tryEmit(Unit)
    }

    private fun importText(text: String, source: String): ImportResult {
        val parsed = JSONObject(ZrayNative.parseLinks(text))
        val items = parsed.optJSONArray("items") ?: JSONArray()
        val servers = List(items.length()) { Server.fromLinkInfo(items.getJSONObject(it), source) }
        val existing = store.byKeys(servers.map { it.key }).map { it.key }.toSet()
        store.upsert(servers)
        serversChanged.tryEmit(Unit)
        return ImportResult(
            added = servers.count { it.key !in existing },
            duplicates = servers.count { it.key in existing },
            rejected = parsed.optInt("rejected"),
        )
    }

    private fun fetchSubscription(sub: Subscription): ImportResult = runCatching {
        val body = httpGet(sub.url)
        val result = importText(body, Server.SOURCE_SUB_PREFIX + sub.id)
        // An answer with nothing in it (a panel's error page, an expired
        // token) would otherwise read as a successful import of nothing.
        if (result.added + result.duplicates + result.rejected == 0) error("no configs in the answer")
        store.upsertSubscription(sub.copy(updatedAt = System.currentTimeMillis(), count = result.added + result.duplicates))
        result
    }.getOrElse { ImportResult(0, 0, 0, it.message ?: "download failed") }

    private suspend fun updateSubscriptions() = withContext(Dispatchers.IO) {
        store.subscriptions().filter { it.enabled }.forEach { fetchSubscription(it) }
    }

    /**
     * Fetch a subscription. While connected, through the app's own tunnel
     * first: the app is excluded from its VPN, and subscription hosts
     * (workers.dev, panel domains) are often filtered on the open network.
     */
    private fun httpGet(url: String): String {
        if (running) {
            val proxy = java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", settings.httpPort))
            runCatching { return httpGet(url, proxy) }.onFailure { Log.w(TAG, "subscription through the tunnel: ${it.message}") }
        }
        return httpGet(url, java.net.Proxy.NO_PROXY)
    }

    private fun httpGet(url: String, proxy: java.net.Proxy): String {
        val conn = URL(url).openConnection(proxy) as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 20_000
        conn.setRequestProperty("User-Agent", "ZeroNet")
        conn.instanceFollowRedirects = true
        try {
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            val bytes = conn.inputStream.use { it.readNBytesCompat(16 * 1024 * 1024) }
            return String(bytes, Charsets.UTF_8)
        } finally {
            conn.disconnect()
        }
    }

    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > limit) error("subscription is larger than 16 MB")
        }
        return out.toByteArray()
    }

    private fun subscriptionId(url: String) =
        java.security.MessageDigest.getInstance("SHA-256").digest(url.toByteArray()).take(6).joinToString("") { "%02x".format(it) }

    private fun hostOf(url: String) = runCatching { URL(url).host }.getOrDefault(url)

    // ---------------------------------------------------------------- scanner

    fun startScan(count: Int) {
        if (scanJob?.isActive == true) return
        scanJob = scope.launch {
            val network = NetworkIdentity.current(app)
            scan.value = ScanState(running = true)
            val request = JSONObject().put("preset", "cloudflare").put("ports", JSONArray(listOf(443, 2053, 8443)))
                .put("host", "www.speedtest.net").put("count", count).put("concurrency", 128).put("timeout_ms", 1500)
            val results = ArrayList<ScanResult>()
            var lastEmit = 0L
            try {
                nativeJob { ZrayNative.scan(request.toString(), it) }.collect { e ->
                    when (e.optString("t")) {
                        "progress" -> scan.value = scan.value.copy(
                            scanned = e.optInt("scanned"), responsive = e.optInt("responsive"), total = e.optInt("total"),
                        )
                        "ip" -> {
                            results += ScanResult(e.optString("ip"), e.optInt("port"), e.optInt("rtt_ms"))
                            val now = System.currentTimeMillis()
                            if (now - lastEmit > 250) {
                                results.sortBy { it.rttMs }
                                scan.value = scan.value.copy(results = results.take(100))
                                lastEmit = now
                            }
                        }
                        "error" -> scan.value = scan.value.copy(error = e.optString("message"))
                    }
                }
            } finally {
                results.sortBy { it.rttMs }
                scan.value = scan.value.copy(running = false, results = results.take(100))
                if (settings.shareResults && network != null && results.isNotEmpty()) {
                    val clean = results.distinctBy { it.ip }.take(Crowd.MAX_CLEAN).map { Crowd.CleanIp(it.ip, it.rttMs) }
                    val tunnel = tunnelProxy()
                    scope.launch(Dispatchers.IO) { Crowd.report(app, network, emptyList(), clean, tunnel) }
                }
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    // ---------------------------------------------------------------- helpers

    private fun teardown() {
        if (running || ZrayNative.isRunning()) {
            ZrayNative.stop()?.let { EngineLog.w("stop: $it") }
        }
        running = false
        pool.clear()
        slowUntil.clear()
        stallSeconds = 0
        lastActiveAt = 0L
        stats.value = TrafficStats()
    }

    private fun fail(reason: FailReason, detail: String) {
        EngineLog.w("failed: $reason${if (detail.isNotBlank()) " — $detail" else ""}")
        publish(ConnState.Failed(reason, detail))
    }

    private fun publish(next: ConnState) {
        state.value = next
        host?.onStateChanged(next)
        ZeroWidget.update(app, next)
    }

    /** Whether the kill switch's placeholder is what carries (drops) traffic right now. */
    val blocking: Boolean get() = blocker != null

    private fun stageOf(name: String) = when (name) {
        "fetch" -> DiscoveryStage.Fetch
        "parse" -> DiscoveryStage.Parse
        "tcp" -> DiscoveryStage.Tcp
        "real" -> DiscoveryStage.Real
        else -> DiscoveryStage.History
    }

    private fun closeFd(fd: Int) {
        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
    }

    /** settings.json is written by the UI process and is the single source of truth. */
    private fun readOptions(): Settings? =
        runCatching { com.zeronet.mobile.data.SettingsStore.readSnapshot(app) }.getOrNull()

    fun snapshotSettings(): Settings = readOptions() ?: settings
}
