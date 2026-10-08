package com.zeronet.mobile.service

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.telephony.TelephonyManager
import android.util.Log
import com.zeronet.mobile.core.LocalProxyAuth
import com.zeronet.mobile.core.ZrayNative
import com.zeronet.mobile.data.NetworkIdentity
import com.zeronet.mobile.data.ServerStore
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.DecoyMode
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
import com.zeronet.mobile.model.RaceState
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.model.classic
import com.zeronet.mobile.model.SpeedFloor
import com.zeronet.mobile.model.TrafficStats
import com.zeronet.mobile.model.WarpConsent
import com.zeronet.mobile.model.WarpOrder
import com.zeronet.mobile.model.WarpPhase
import com.zeronet.mobile.model.WarpState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
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
        ConnectionProfile.Normal, ConnectionProfile.Legacy -> WANT_ALIVE
        ConnectionProfile.Fast -> 1
        ConnectionProfile.Gaming -> 3
    }

    private fun stopDiscoveryAt(p: ConnectionProfile) = when (p) {
        ConnectionProfile.Normal, ConnectionProfile.Legacy -> STOP_DISCOVERY_AT
        ConnectionProfile.Fast -> 1
        ConnectionProfile.Gaming -> 2
    }

    /** How many pool members go into the config: the rest are standby for the health check. */
    private fun linksInConfig(p: ConnectionProfile) = when (p) {
        ConnectionProfile.Normal, ConnectionProfile.Legacy -> WANT_ALIVE
        ConnectionProfile.Fast, ConnectionProfile.Gaming -> 1
    }

    /** Whether a discovered or stored server suits the profile. A server the user picked always does. */
    private fun suits(server: Server, p: ConnectionProfile): Boolean {
        if (excludedByCountry(server)) return false
        // The last rung of the ladder takes anything that works.
        if (rung?.relaxed == true) return true
        return when (p) {
            ConnectionProfile.Normal, ConnectionProfile.Legacy -> server.security == "tls" || server.security == "reality" ||
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
    /** How often the connected client quietly looks for more servers (see [maybeBackgroundFind]). */
    private const val BACKGROUND_FIND_MS = 45 * 60_000L
    /** No user traffic for this long before a background search may start. */
    private const val BACKGROUND_FIND_QUIET_MS = 30_000L

    // ---- speed-based switching -------------------------------------------------
    /** Seconds of real traffic the slow decision looks at. */
    private const val SPEED_WINDOW = 20
    /** A one-second sample below this is not the user transferring anything. */
    private const val MIN_ACTIVE_BPS = 4_000L
    /** Fronted variants of past public finds tested per search (matches the desktop finder). */
    private const val FRONT_VARIANTS = 18
    private const val WARP_STEPS_KEPT = 6
    /**
     * How long the automatic setup lets one registration and its search for
     * servers run. It bounds the work the core does; the wait around it is
     * longer, so a job that reports nothing at all cannot hold the connect.
     */
    private const val WARP_BOOT_BUDGET_MS = 30_000L
    private const val WARP_BOOT_WAIT_MS = 90_000L
    /** Gaming times this many servers, this many times each, before settling on one. */
    private const val GAME_TUNE_SERVERS = 5
    private const val GAME_TUNE_ROUNDS = 3
    /** Shortest gap between two screen-on/unlock tunnel checks. */
    private const val UNLOCK_CHECK_GAP_MS = 10_000L
    /** Upload rate that counts as real use on its own (matches the desktop
     *  watchdog's `UPLOAD_ALIVE_BPS`). */
    private const val UPLOAD_ALIVE_BPS = 32L * 1024
    /** At least this many of the window's samples must be active to judge speed. */
    private const val ACTIVE_SAMPLES = 6
    /** Active seconds out of [SPEED_WINDOW] before the adaptive floor treats
     *  the window as a bulk transfer worth measuring. */
    private const val SUSTAINED_SAMPLES = 10
    /** Silence this long, with connections still open, counts as a stall. */
    private const val STALL_AFTER_MS = 15_000L
    /** Past this, the silence is ordinary idleness, not a stalled download. */
    private const val STALL_GIVEUP_MS = 45_000L
    /** A server switched away from for being slow is not used again until this passes. */
    private const val SLOW_COOLDOWN_MS = 10 * 60_000L
    /** Saved servers per family the self-test tries. */
    private const val FAMILY_SAMPLE = 4

    /** The way of the ladder being tried, or being used once one worked; null outside the recommended mode. */
    @Volatile private var rung: Ladder.Rung? = null

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
    /** One replacement search at a time, from the switch path or the periodic one. */
    private var replacementJob: Job? = null
    /** Health checks in a row in which the chosen config failed; see [CHOSEN_DOWN_AFTER]. */
    private var chosenFailures = 0
    private val healthNow = Channel<Unit>(Channel.CONFLATED)
    /** Wakes the kill-switch retry loop early (a network change). */
    private val retryNow = Channel<Unit>(Channel.CONFLATED)
    /** Last byte through the tunnel; the periodic background search waits for a quiet moment. */
    @Volatile private var lastTrafficAt = 0L
    /** Last time the background search ran; a connect resets the clock. */
    @Volatile private var lastBackgroundFindAt = 0L
    /** The unlock recovery is one-shot per unlock; this keeps two from stacking. */
    @Volatile private var unlockRecovery = false
    @Volatile private var lastUnlockCheckAt = 0L

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

    /** Notices the core's tunnel device closing under a connection that still says it is up. */
    private val tunWatch = TunWatch()

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
    /** Learns recent configs' delivered speeds for [SpeedFloor.Adaptive]. */
    private val adaptiveFloor = AdaptiveFloor()
    /** The primary whose speed [adaptiveFloor] is currently accumulating. */
    private var adaptivePrimaryKey: String? = null
    /** Best sustained throughput seen on the current primary, bytes/s. */
    private var adaptivePeakBps = 0L
    /** Seconds the current primary has been primary: the shared speed history
     *  still holds the previous server's samples until a full window passes. */
    private var adaptiveSeconds = 0
    /** Set on a network move; the speed monitor then forgets its baseline. */
    @Volatile private var adaptiveResetPending = false
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
    /** Others on this network got through better fragmented: start that way. */
    @Volatile private var crowdFragmentFirst = false
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
        // Before the core builds a config: the rule sets must already be in
        // place for the config to use them.
        com.zeronet.mobile.data.GeoAssets.install(app)?.let { EngineLog.e("rule sets: $it") }
        nativeError = runCatching { ZrayNative.init(app.filesDir.absolutePath, coreLogLevel(settings)) }
            .fold({ it }, { "native library failed to load: ${it.message}" })
        if (nativeError != null) EngineLog.e("native init: $nativeError")
        // The finder tests servers before any config is built, so the core
        // hears about the decoy switch as soon as it is loaded.
        else runCatching { ZrayNative.setDecoy(settings.sniDecoy != DecoyMode.Off) }
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
            if (warpBootstrapWanted()) {
                // The setup ends by connecting the account or by failing;
                // either way it has already dialled.
                warpBooting = true
                try {
                    runWarpBootstrap()
                } finally {
                    warpBooting = false
                }
            } else {
                mutex.withLock { runConnection() }
            }
            afterConnectAttempt()
        }
    }

    /**
     * Whether this connect should set a Cloudflare WARP account up first.
     *
     * Only the recommended mode, only when the answer is [WarpConsent.On] (the
     * question itself is asked by the UI, once), and only while no account
     * exists: an account that is already there is just another server the
     * ladder tries.
     */
    private suspend fun warpBootstrapWanted(): Boolean =
        settings.warpConsent == WarpConsent.On &&
            settings.profile == ConnectionProfile.Normal &&
            !hasWarpAccount()

    /**
     * Whether an account is already stored: a server whose link is a `warp://`
     * one. Once it exists the setup has nothing left to do, and the account is
     * just another server the ladder tries.
     */
    private suspend fun hasWarpAccount(): Boolean =
        withContext(Dispatchers.IO) { store.hasWarpAccount() }

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
        noteSessionEnd()
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
        if (moved) {
            EngineLog.i("network changed (${NetworkIdentity.label(app).ifBlank { "unknown" }})")
            // Speeds learned on the last network say nothing about this one:
            // fibre's baseline would condemn every server on mobile data.
            // Cleared by the monitor, which owns that state, not from this
            // callback thread.
            adaptiveResetPending = true
        }
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
                val all = withContext(Dispatchers.IO) { store.inSubscriptions(t.ids) }
                val usable = all.filter { !it.excluded }
                testAndCollect(usable.filter { it.key !in excludeKeys }.ifEmpty { usable }, network)
            }
            else -> discover(network, excludeKeys)
        }
    }

    private fun topology(s: Settings) = listOf(s.lanShare, s.lanUser, s.lanPass, s.socksPort, s.httpPort)

    private fun routing(s: Settings) = listOf(
        s.iranDirect, s.blockQuic, s.evasion, s.sniDecoy, s.fragmentPackets, s.remoteDns, s.customDns,
        s.antiSanctionDns, s.customAntiSanction, s.blockAds, s.logs, s.activeRoutingRules,
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
        tunWatch.reset()
        rung = null
        replacements = 0
        connectStartedAt = System.currentTimeMillis()
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
                    val candidates = withContext(Dispatchers.IO) { store.inSubscriptions(t.ids) }
                    if (candidates.isEmpty()) { fail(FailReason.ServerUnavailable, ""); return }
                    testAndCollect(candidates, network)
                    if (!running) { fail(FailReason.NoWorkingServer, ""); return }
                }
                ConnectTarget.Fastest -> {
                    if (settings.profile == ConnectionProfile.Normal) {
                        climbLadder(network)
                    } else {
                        val tried = tryKnownFirst(network)
                        if (pool.size < stopDiscoveryAt(settings.profile)) discover(network, excludeKeys = tried)
                    }
                    // How long a connect took, or that it did not come up: the plainest measure of a mode.
                    noteMode("connect", running, (System.currentTimeMillis() - connectStartedAt).toInt())
                    if (!running) { reportCrowd(network); fail(FailReason.NoWorkingServer, ""); return }
                }
            }
            reportCrowd(network)
            lastBackgroundFindAt = System.currentTimeMillis()
            monitorJob = scope.launch { monitor(network) }
            if (settings.profile == ConnectionProfile.Gaming) scope.launch { tuneForGaming() }
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
     * Gaming: a few seconds after the tunnel is up, and before a match is
     * likely to have started, time the servers in the pool several times and
     * move the steadiest to the front (see [GameTune]). One switch at most;
     * a server that is only marginally better is not worth dropping a
     * connection for.
     */
    private suspend fun tuneForGaming() {
        val candidates = mutex.withLock { usablePool().map { it.server } }.take(GAME_TUNE_SERVERS)
        if (candidates.size < 2) return
        val timings = HashMap<String, MutableList<Int>>()
        repeat(GAME_TUNE_ROUNDS) {
            if (!running) return
            testServers(candidates, timeoutMs = 2_500, concurrency = candidates.size) { key, delay, _ ->
                timings.getOrPut(key) { mutableListOf() } += delay
            }
        }
        mutex.withLock {
            if (!running || settings.profile != ConnectionProfile.Gaming) return
            val current = usablePool().firstOrNull()?.server?.key
            val best = GameTune.pick(timings, current)
            if (best == null || best == current) {
                EngineLog.i("gaming: the server in use is already the steadiest")
                return
            }
            val at = pool.indexOfFirst { it.server.key == best }
            if (at < 0) return
            EngineLog.i("gaming: moving to the steadiest server, ${describe(pool[at].server)}")
            pool.add(0, pool.removeAt(at))
            reloadPool()
        }
    }

    /**
     * The recommended mode's search: the ways of the [Ladder], fastest first,
     * until the tunnel is up. The way that worked is remembered for this
     * network and tried straight after the quick first one next time.
     */
    private suspend fun climbLadder(network: String) {
        val prefs = app.getSharedPreferences("ladder", Context.MODE_PRIVATE)
        val warpServers = withContext(Dispatchers.IO) { store.userServers().filter { it.fingerprint.isNotEmpty() && !it.excluded } }
        val order = Ladder.order(Ladder.indexOf(prefs.getString("net:$network", null)), hasWarp = warpServers.isNotEmpty())
        var tried = emptySet<String>()
        for ((step, index) in order.withIndex()) {
            val way = Ladder.rungs[index]
            rung = way
            EngineLog.i("way ${step + 1} of ${order.size}: ${way.id}")
            publish(ConnState.Searching(DiscoveryProgress(method = way.id)))
            when {
                way.known -> tried = tryKnownFirst(network)
                way.warp -> testAndCollect(warpServers, network)
                else -> discover(network, excludeKeys = tried)
            }
            if (running) {
                prefs.edit().putString("net:$network", way.id).apply()
                EngineLog.i("connected by way ${way.id}")
                // The pool can still grow in the background, by the way that worked.
                if (pool.size < stopDiscoveryAt(settings.profile) && way.known) {
                    rung = Ladder.rungs[Ladder.SEARCH]
                    discover(network, excludeKeys = tried)
                }
                return
            }
        }
        rung = null
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
        crowdFragmentFirst = rankings?.let { Crowd.fragmentFirst(it, crowdName) } ?: false
        val history = withContext(Dispatchers.IO) { store.historyLinks(network, 12) }
        val links = (history + picks.map { it.link }).distinct()
        if (links.isEmpty()) return emptySet()

        val items = JSONObject(ZrayNative.parseLinks(links.joinToString("\n"))).optJSONArray("items") ?: JSONArray()
        val parsed = List(items.length()) { Server.fromLinkInfo(items.getJSONObject(it), Server.SOURCE_FEED_PREFIX + "crowd") }
        // A server already stored keeps its record: its source says whether it is the user's own.
        val stored = withContext(Dispatchers.IO) { store.byKeys(parsed.map { it.key }) }.associateBy { it.key }
        val candidates = parsed.map { stored[it.key] ?: it }.distinctBy { it.key }
            .filter { suits(it, settings.profile) && !it.excluded }
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
        if (!settings.shareResults) return
        // How the modes did, kept from earlier sessions until there is a tunnel to send through.
        val modes = ModeStats.pending(app)
        if (results.isEmpty() && modes.length() == 0) return
        val tunnel = tunnelProxy()
        scope.launch(Dispatchers.IO) {
            val sent = Crowd.report(app, network, results, emptyList(), tunnel, modes = modes.takeIf { it.length() > 0 })
            if (sent && modes.length() > 0) ModeStats.sent(app, modes.length())
        }
    }

    /** Remember how the mode in use did, for the anonymous report, when the user allows it. */
    private fun noteMode(metric: String, ok: Boolean, ms: Int? = null) {
        if (!settings.shareResults) return
        ModeStats.record(app, ModeStats.Fact(ModeStats.id(settings.profile, metric), ok, ms))
    }

    /** The server changes made since this connection came up; a steady one made none. */
    @Volatile private var replacements = 0

    /** When the running connect began. */
    @Volatile private var connectStartedAt = 0L

    /** A session ended: how it went, if it lasted long enough to say. */
    private fun noteSessionEnd() {
        if (!running || since == 0L) return
        val lasted = System.currentTimeMillis() - since
        ModeStats.stableSession(lasted, replacements)?.let { noteMode("stable", it) }
        usablePool().firstOrNull()?.delayMs?.takeIf { it >= 0 }?.let { noteMode("ping", true, it) }
    }

    /** The last method measurement reported, with its network, so each one is
     *  sent once rather than every second. */
    private var reportedMethods: String? = null

    /**
     * Share what the core measured about built-in techniques (CDN handling,
     * which anti-sanction resolver relays) when the user allows it: once per
     * new measurement, filed under the network it was measured on. The core
     * measures a few seconds after connecting, so this runs from the stats
     * loop rather than with the connect's server results.
     */
    private fun reportMethods(methods: org.json.JSONArray, network: String) {
        val key = "$network|$methods"
        if (!settings.shareResults || key == reportedMethods) return
        reportedMethods = key
        val tunnel = tunnelProxy()
        scope.launch(Dispatchers.IO) { Crowd.report(app, network, emptyList(), emptyList(), tunnel, methods) }
    }

    /** The local HTTP proxy into the tunnel, while it is up. */
    private fun tunnelProxy(): java.net.Proxy? =
        if (running) java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", settings.httpPort)) else null

    /**
     * BPB-style fronting: the public servers that worked here before, re-aimed
     * at a bounded sample of Cloudflare edge IPs, so one whose written address
     * or port got blocked is still reached through an edge that is not.
     *
     * The user's own configs are never fronted. A fronted variant is a new
     * link, found and reported like any public find, so fronting a personal
     * worker would put its name into the crowd report.
     */
    private fun frontedVariants(history: List<String>, userServers: List<Server>, max: Int = FRONT_VARIANTS): List<String> {
        val own = userServers.mapTo(HashSet()) { it.link }
        val public = history.filter { it !in own }
        if (public.isEmpty()) return emptyList()
        val request = JSONObject()
            .put("links", JSONArray(public))
            .put("seed", frontSeed())
            .put("max", max)
        return runCatching {
            val answer = JSONObject(ZrayNative.frontLinks(request.toString()))
            val links = answer.optJSONArray("links") ?: JSONArray()
            List(links.length()) { links.getString(it) }
        }.onFailure { EngineLog.w("fronting skipped: ${it.message}") }.getOrDefault(emptyList())
    }

    /**
     * This install's fronting seed: fixed here, so probe evidence builds up
     * against the same edges, but different between installs, so not every
     * phone leans on the same few addresses. Local only, never sent anywhere.
     */
    private fun frontSeed(): Long {
        val prefs = app.getSharedPreferences("fronting", android.content.Context.MODE_PRIVATE)
        if (prefs.contains("seed")) return prefs.getLong("seed", 0L)
        // Non-negative: the core reads it as an unsigned number.
        val seed = java.security.SecureRandom().nextLong() and Long.MAX_VALUE
        prefs.edit().putLong("seed", seed).apply()
        return seed
    }

    /** Stream discovery; bring the tunnel up on the first working config. */
    private suspend fun discover(network: String, excludeKeys: Set<String>) {
        val history = withContext(Dispatchers.IO) { store.historyLinks(network, 12) }
        val userServers = withContext(Dispatchers.IO) { store.userServers() }
        val request = JSONObject()
            .put("sources", Sources.toJson(Sources.enabled(settings.disabledSources)))
            .put("cache_dir", File(app.cacheDir, "feeds").apply { mkdirs() }.absolutePath)
            .put("priority_links", JSONArray(history + frontedVariants(history, userServers, rung?.fronts ?: FRONT_VARIANTS)))
            .put("extra_links", JSONArray(userServers.filter { !it.excluded }.map { it.link }))
            // Servers the user excluded are skipped even when a feed lists them again.
            .put("exclude_keys", JSONArray((excludeKeys + withContext(Dispatchers.IO) { store.excludedKeys() }).toList()))
            .put("want_alive", wantAlive(settings.profile))
            .put("max_seconds", rung?.budgetSeconds ?: 75)
            .put("tcp_concurrency", 256).put("tcp_timeout_ms", 1500).put("tcp_stop_after_open", 1500)
            .put("real_concurrency", 64).put("real_timeout_ms", 3000)
            .put("probe_url", PROBE_URL)
            .put("next_tier_if_alive_below", 3)
            .put("fetch", true)
        var progress = DiscoveryProgress(method = rung?.id.orEmpty())
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
    private suspend fun testAndCollect(servers: List<Server>, network: String) {
        // A server the user excluded is never picked automatically, even from
        // a chosen country or subscription.
        val all = servers.filter { !it.excluded }
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
        runCatching { ZrayNative.setDecoy(s.sniDecoy != DecoyMode.Off) }
        val request = JSONObject()
            .put("links", JSONArray(links.map { it.server.link }))
            .put("mode", if (s.mode == ConnectionMode.Vpn) "vpn" else "proxy")
            .put("tun", JSONObject().put("mtu", s.mtu).put("ipv6", s.ipv6))
            .put("socks_port", s.socksPort).put("http_port", s.httpPort)
            .put("lan", JSONObject().put("enabled", s.lanShare).put("listen", "0.0.0.0").put("user", s.lanUser).put("pass", s.lanPass))
            // Keeps other apps on the phone out of the local proxy in VPN mode.
            .put("local_auth", JSONObject().put("user", LocalProxyAuth.user).put("pass", LocalProxyAuth.pass))
            // Games and voice run over UDP: Gaming never blocks it.
            .put("iran_direct", s.iranDirect).put("block_ads", s.blockAds)
            .put("block_quic", s.blockQuic && s.profile != ConnectionProfile.Gaming && rung?.allowQuic != true)
            // Fragmenting the ClientHello costs round trips; Fast and Gaming skip it.
            .put("evasion", if (!s.profile.classic) "off" else when (rung?.evasion ?: s.evasion) { EvasionLevel.Off -> "off"; EvasionLevel.Auto -> "auto"; EvasionLevel.Strong -> "strong" })
            .put("fragment_first", crowdFragmentFirst)
            // The decoy server name: on every connection, or never as a variant.
            // Left to the core under Auto.
            .put("sni_spoof", s.sniDecoy == DecoyMode.Always)
            .apply { if (s.sniDecoy == DecoyMode.Off) put("auto_decoy", false) }
            .put("fragment_packets", s.fragmentPackets.trim().ifEmpty { "1-1" })
            .put("dns", JSONObject().put("remote", s.remoteDns.name.lowercase()).put("custom", s.customDns.trim()).put("local", "google").put("anti_sanction", s.antiSanctionDns.name.lowercase()).put("custom_anti_sanction", s.customAntiSanction.trim()).put("fakedns", s.fakeDns))
            // The user's own scan first, then what others found on this network.
            .put("clean_ips", JSONArray((scan.value.results.take(10).map { "${it.ip}:${it.port}" } + crowdCleanIps).distinct().take(20)))
            .put("log_level", if (s.logs) "info" else "warning")
            .put("warp_order", s.warpOrder.wire)
            // The user's routing profile, ahead of the built-in rules.
            .put("routing_rules", JSONArray(s.activeRoutingRules.map { it.toJson() }))
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
                o.optJSONObject("race")?.let { race.value = Ipc.raceFromJson(it) }
                val next = TrafficStats(upRate, downRate, up, down, downHistory.toList(), upHistory.toList(), o.optString("cdn"))
                o.optJSONArray("methods")?.takeIf { it.length() > 0 }?.let { reportMethods(it, NetworkIdentity.current(app) ?: network) }
                stats.value = next
                if (interactive && tick % 2 == 0L) host?.onStats(next)
                if (upRate + downRate > 0) lastTrafficAt = System.currentTimeMillis()
                maybeSwitchOnSpeed(downRate, upRate, sessions, downHistory)
                if (settings.mode == ConnectionMode.Vpn) watchTunnelDevice(o.optBoolean("tun_lost"))
            }
            if (forced || (settings.autoSwitch && tick * 1000 % HEALTH_INTERVAL_MS == 0L)) {
                healthCheck(NetworkIdentity.current(app) ?: network)
            }
            maybeBackgroundFind(NetworkIdentity.current(app) ?: network)
        }
    }

    /**
     * The VPN interface can close while the core carries on (the system took
     * it away, another VPN started): the key leaves the status bar and no byte
     * enters the tunnel, yet nothing else would change the state from
     * "connected". When the core reports its device gone, bring the interface
     * back; if it keeps closing, stop and say so.
     */
    private suspend fun watchTunnelDevice(lost: Boolean) {
        when (tunWatch.observe(lost, System.currentTimeMillis())) {
            TunWatch.Verdict.Fine -> Unit
            TunWatch.Verdict.Recover -> mutex.withLock {
                if (!running) return@withLock
                EngineLog.w("the VPN interface closed while connected: bringing it back")
                restartCore()
            }
            TunWatch.Verdict.GiveUp -> {
                EngineLog.w("the VPN interface keeps closing: giving up")
                connectJob?.cancel()
                monitorJob?.cancel()
                scope.launch {
                    mutex.withLock {
                        teardown()
                        releaseBlocker()
                        fail(FailReason.CoreError, "the VPN interface keeps closing")
                    }
                    host?.finish()
                    host = null
                }
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
        val now = System.currentTimeMillis()
        // Bytes coming back are the proof a tunnel works; outgoing bytes are
        // counted before anything answers, so a dead tunnel that apps keep
        // retrying still "uploads". Upload alone only counts at a real upload
        // rate, otherwise a stalled connection never looks stalled.
        val moving = downRate > MIN_ACTIVE_BPS || upRate >= UPLOAD_ALIVE_BPS
        if (moving) lastActiveAt = now

        // Adaptive floor: remember the best *sustained* download speed each
        // config reached, and judge the current one against what the recent
        // ones delivered. Only a real bulk transfer is a measurement (see
        // sustainedDownload): light browsing never fills the pipe, so its
        // speed says nothing about the server. The per-config best is banked
        // when the primary changes.
        val adaptive = settings.speedFloor == SpeedFloor.Adaptive
        if (adaptiveResetPending) {
            adaptiveResetPending = false
            adaptiveFloor.clear()
            adaptivePrimaryKey = null
            adaptivePeakBps = 0
            adaptiveSeconds = 0
        }
        val window = downHistory.toList().takeLast(SPEED_WINDOW)
        var sustained: Long? = null
        if (adaptive) {
            val primaryKey = pool.firstOrNull()?.server?.key
            if (primaryKey != adaptivePrimaryKey) {
                if (adaptivePeakBps > 0) adaptiveFloor.record(adaptivePeakBps)
                adaptivePrimaryKey = primaryKey
                adaptivePeakBps = 0
                adaptiveSeconds = 0
            }
            adaptiveSeconds++
            // Only a window that belongs entirely to this server measures it.
            if (adaptiveSeconds >= SPEED_WINDOW && window.size >= SPEED_WINDOW) {
                sustained = sustainedDownload(window, MIN_ACTIVE_BPS, SUSTAINED_SAMPLES)
            }
            sustained?.let { adaptivePeakBps = maxOf(adaptivePeakBps, it) }
        }
        val floor = if (adaptive) adaptiveFloor.effectiveFloorBps() else settings.speedFloorBytes
        // Off turns speed switching off entirely, stall checks included.
        // Adaptive with no baseline yet still catches a stall, but never drops
        // a server for being slow.
        if (!adaptive && floor <= 0) return

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
        val slow = if (adaptive) {
            // Like against like: this config's sustained speed next to the
            // sustained speeds recent configs reached.
            sustained != null && adaptiveFloor.tooSlow(sustained)
        } else {
            val active = window.count { it > MIN_ACTIVE_BPS } >= ACTIVE_SAMPLES
            val peak = window.maxOrNull() ?: 0L
            val avg = window.sum() / window.size
            active && peak < floor && avg < floor
        }
        if (slow && now - lastSlowSwitchAt > SLOW_COOLDOWN_MS) {
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
        replacements++
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
        launchReplacementSearch(network, excludeKeys = pool.map { it.server.key }.toSet())
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

    // -------------------------------------------------------------- failsafes

    /**
     * The screen was unlocked after a locked stretch: the moment the user is
     * about to use the phone, and the moment a tunnel that quietly died in
     * doze has to be noticed. While locked, a NAT rebind or a silent
     * Wi-Fi ↔ cellular move can leave the tunnel up but carrying nothing, and
     * the monitor's cadence is suspended in doze with everything else.
     *
     * The check is one 204 request through the local proxy, so a working
     * tunnel costs nothing. Only when traffic does not move: rebind the
     * pooled QUIC and WireGuard connections onto the current network, check
     * the servers (the health check replaces the dead ones or searches), and
     * restart the core when the servers answer but the tunnel still will not
     * carry traffic.
     */
    fun onUnlocked() {
        if (!running || unlockRecovery) return
        // Screen-on and unlock usually arrive together; one check covers both.
        val now = System.currentTimeMillis()
        if (now - lastUnlockCheckAt < UNLOCK_CHECK_GAP_MS) return
        lastUnlockCheckAt = now
        unlockRecovery = true
        scope.launch {
            try {
                if (tunnelCarriesTraffic()) return@launch
                EngineLog.i("screen unlocked: the tunnel is not carrying traffic — recovering")
                homeCountry = detectHomeCountry()
                runCatching { ZrayNative.networkChanged() }
                // The rebind may have been the whole problem (the pooled
                // connections moved networks while the phone was locked).
                if (tunnelCarriesTraffic()) return@launch
                healthCheck(NetworkIdentity.current(app))
                if (!running) return@launch
                if (tunnelCarriesTraffic()) return@launch
                if (target is ConnectTarget.Specific) {
                    // The chosen config is dead and the health check never
                    // swaps it: reconnecting to it is the honest retry.
                    reconnect()
                } else {
                    EngineLog.i("screen unlocked: servers answer but the tunnel stays dead — restarting the core")
                    mutex.withLock { restartCore() }
                }
            } finally {
                unlockRecovery = false
            }
        }
    }

    /** One small request through the local proxy: does the tunnel carry traffic right now. */
    private suspend fun tunnelCarriesTraffic(): Boolean = withContext(Dispatchers.IO) {
        runCatching { Diagnostics.tunnel(settings.httpPort).status == CheckStatus.Ok }.getOrDefault(false)
    }

    /**
     * Every so often, while connected and the user's traffic is quiet, test a
     * fresh batch of public servers and — when the user shares results —
     * report the working ones. The finds go into the pool as standby backups
     * for the health check, and the reports are what keep the crowd's picture
     * of this network current for everyone else.
     *
     * Bounded like the connect-time background search (a couple of servers,
     * 20 s once the tunnel is up), so the cost is one conditional feed
     * download and a few hundred small probes, once every [BACKGROUND_FIND_MS].
     * Skipped in Gaming (its contract is that the server never changes
     * mid-match) and for a specific chosen config (the user picked one server;
     * the feeds have nothing to add to it).
     */
    private fun maybeBackgroundFind(network: String?) {
        if (network == null) return
        if (settings.profile == ConnectionProfile.Gaming || target !is ConnectTarget.Fastest) return
        if (backgroundFindGuarded()) return
        val now = System.currentTimeMillis()
        if (now - lastBackgroundFindAt < BACKGROUND_FIND_MS) return
        if (now - lastTrafficAt < BACKGROUND_FIND_QUIET_MS) return
        lastBackgroundFindAt = now
        EngineLog.i("quiet tunnel: looking for more servers in the background")
        launchReplacementSearch(network, excludeKeys = pool.map { it.server.key }.toSet())
    }

    /** `true` while a replacement search or a user-triggered job owns the search slot. */
    private fun backgroundFindGuarded() =
        replacementJob?.isActive == true || refreshJob?.isActive == true || testJob?.isActive == true

    /**
     * Run one replacement search and report its results, one at a time. Used
     * after a switch (the next switch needs somewhere to go) and by the
     * periodic quiet search; both feed the same crowd report.
     */
    private fun launchReplacementSearch(network: String, excludeKeys: Set<String>) {
        if (replacementJob?.isActive == true) return
        replacementJob = scope.launch {
            try {
                findReplacements(network, excludeKeys)
                reportCrowd(network)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                EngineLog.w("replacement search: ${e.message.orEmpty()}")
            }
        }
    }

    // ------------------------------------------------------------------ warp

    val warp = MutableStateFlow(WarpState())

    /** The last WARP route race, read from the core with each stats tick. */
    val race = MutableStateFlow(RaceState())
    private var warpJob: Job? = null
    /**
     * The automatic setup is running. It and [warpStart] both write [warp] and
     * both run a registration in the core, so they take turns rather than
     * interleaving their progress lines.
     */
    @Volatile private var warpBooting = false

    /**
     * Get a Cloudflare WARP account: the native job makes the keys on the
     * phone, registers them, and looks for servers that work through the
     * account. When the tunnel is up the request goes through it, since the
     * service may be filtered by name. On success the account's link is
     * imported like any other server.
     */
    fun warpStart() {
        // The automatic setup owns the account while it runs; starting a
        // second registration now would interleave their progress lines.
        if (warpJob?.isActive == true || warpBooting) return
        warp.value = WarpState(WarpPhase.Working)
        warpJob = scope.launch(Dispatchers.IO) {
            try {
                val request = JSONObject().put("direct", true).put("order", settings.warpOrder.wire)
                if (running) request.put("proxy", "127.0.0.1:${settings.httpPort}").put("proxyAuth", LocalProxyAuth.userPass)
                var steps = emptyList<String>()
                var finished = false
                nativeJob { ZrayNative.warpRegister(request.toString(), it) }.collect { e ->
                    when (e.optString("t")) {
                        "step" -> {
                            EngineLog.i("warp: ${e.optString("line")}")
                            steps = (steps + e.optString("line")).takeLast(WARP_STEPS_KEPT)
                            warp.value = WarpState(WarpPhase.Working, steps)
                        }
                        "done" -> {
                            finished = true
                            if (e.optBoolean("ok")) {
                                val link = e.optString("link")
                                val result = import(link)
                                warp.value = if (result.added + result.duplicates > 0) {
                                    WarpState(
                                        WarpPhase.Done, steps, e.optString("fingerprint"),
                                        e.optInt("exits"), e.optString("route"),
                                    )
                                } else {
                                    WarpState(WarpPhase.Failed, steps, error = result.error ?: "import")
                                }
                            } else {
                                warp.value = WarpState(WarpPhase.Failed, steps, error = e.optString("error"))
                            }
                        }
                    }
                }
                if (!finished) warp.value = WarpState(WarpPhase.Failed, steps, error = "cancelled")
            } catch (e: CancellationException) {
                warp.value = WarpState()
                throw e
            } catch (e: Throwable) {
                EngineLog.w("warp: ${e.message.orEmpty()}")
                warp.value = WarpState(WarpPhase.Failed, warp.value.steps, error = e.message.orEmpty())
            }
        }
    }

    fun warpCancel() {
        warpJob?.cancel()
        warpJob = null
        // The setup is not cancelled here: it is part of a connect, and
        // cancelling it would leave a borrowed tunnel up. Only its progress
        // display goes away with the sheet.
        if (!warpBooting) warp.value = WarpState()
    }

    // ------------------------------------------------- the automatic setup
    //
    // The one-shot setup the connect flow runs the first time: ask about
    // Cloudflare, make the account, let any borrowed server go, and dial the
    // account, whose tunnel and found servers go in the order the settings
    // ask for (`warp_order`). The order and the rules are the same ones the
    // desktop TUI runs (`warp_bootstrap` in `zeronet-tui`); this is the part
    // that waits and dials.

    /**
     * Set a Cloudflare WARP account up and connect it, as part of a connect
     * the person already asked for.
     *
     * The service is tried directly first, with a short deadline. When nothing
     * answers — Cloudflare is filtered by name on many Iranian networks — a
     * server is brought up to make the account through, and let go again the
     * moment the account exists, so the tunnel is not rebuilt on top of
     * itself. Every way this can fail falls back to an ordinary connect, so
     * pressing connect always connects to something.
     */
    private suspend fun runWarpBootstrap() {
        // The connect that was asked for. Restored whenever the setup does not
        // end by dialling an account, so the fallback is exactly the connect
        // the person pressed, not a half-finished account.
        val asked = target
        // A tunnel this setup is responsible for letting go again: the one it
        // borrows for the trip, and the one it was handed when it started.
        var borrowed = false
        warp.value = WarpState(WarpPhase.Working)
        // The setup can take a while (a short probe, then a registration and a
        // search for servers that work through it). Say something, so the orb
        // and the notification do not read as a connect that has hung.
        publish(ConnState.Searching(DiscoveryProgress()))

        try {
            val made = when {
                // Already online: the service is filtered by name, so the
                // tunnel in hand is the one path there that works.
                running -> {
                    borrowed = true
                    registerAccount()
                }
                else -> {
                    // A short question first: is Cloudflare reachable from here
                    // at all? A filtered address answers nothing, so without
                    // the short deadline this would cost the full registration
                    // timeout every time.
                    val probe = registerAccount(quick = true)
                    when {
                        probe.account != null -> {
                            EngineLog.i("warp: the account was made directly")
                            probe
                        }
                        // It answered and refused. A rate limit or an HTTP error
                        // means the service *was* reached, so a tunnel would
                        // change nothing.
                        !probe.unreachable -> {
                            warpFail(probe, probe.error ?: "the WARP service did not answer")
                            fallbackConnect(asked)
                            return
                        }
                        else -> {
                            EngineLog.i("warp: ${probe.error} — borrowing a server to make the account through")
                            borrowed = true
                            // The finally below lets this tunnel go whatever
                            // happens next, including a cancel or a failure.
                            try {
                                mutex.withLock { runConnection() }
                                if (!running) {
                                    // The borrow *was* the connect the person
                                    // asked for, so there is nothing left to
                                    // fall back to: it already failed.
                                    warp.value = WarpState(
                                        WarpPhase.Failed, probe.steps,
                                        error = "No server answered, so the account could not be made through one.",
                                    )
                                    return
                                }
                                registerAccount()
                            } finally {
                                // The flag is cleared here as well as the
                                // tunnel: the release below must not run a
                                // second time over a tunnel already gone.
                                if (borrowed) { releaseBorrowed(); borrowed = false }
                            }
                        }
                    }
                }
            }

            if (borrowed) releaseBorrowed()
            if (made.account == null) {
                warpFail(made, made.error ?: "the account was not made")
                fallbackConnect(asked)
                return
            }
            dialAccount(asked, made)
        } catch (e: CancellationException) {
            // A disconnect arriving mid-setup still has to let go of a tunnel
            // the person never chose.
            if (borrowed) releaseBorrowed()
            throw e
        } catch (e: Throwable) {
            // An escape here would take the whole engine process with it and
            // leave the kill switch holding traffic with nothing to release it.
            EngineLog.e("warp setup", e)
            if (borrowed) releaseBorrowed()
            warp.value = WarpState(WarpPhase.Failed, warp.value.steps, error = e.message.orEmpty())
            fallbackConnect(asked)
        }
    }

    /**
     * Let go the tunnel the setup borrowed, before the account is dialled.
     *
     * The core holds one configuration at a time, so the account cannot be
     * dialled on top of whatever is running now. This is the one rule the
     * desktop states plainly: once a server has been borrowed it is always let
     * go, even when the account could not be made, because a failure must
     * never leave the person on a server they did not choose.
     *
     * The teardown is not cancellable, and the kill switch is put back up
     * *before* the tunnel goes, so nothing slips out in between.
     *
     * `NonCancellable` wraps the lock, not the block inside it: taking a
     * `Mutex` is itself a cancellable suspend call, so a teardown reached from
     * a cancel (this is the one the borrow path's `finally` runs on) would
     * otherwise give up at `withLock` whenever something else — a disconnect,
     * a revocation — was already holding the lock, and leave the tunnel up.
     */
    private suspend fun releaseBorrowed() {
        if (!running && blocker == null) return
        withContext(NonCancellable) {
            mutex.withLock {
                holdBlocker()
                monitorJob?.cancel()
                teardown()
            }
        }
        EngineLog.i("warp: let the borrowed server go")
    }

    /**
     * Store the account and dial it: the WARP tunnel and the servers found
     * for it, in the order the settings ask for. `asked` is the connect being
     * replaced, restored if this fails.
     */
    private suspend fun dialAccount(asked: ConnectTarget, made: WarpAccount) {
        val account = made.account ?: return
        // Whatever is running now has to go first: the core takes one config,
        // and a start on top of a live tunnel fails and leaves a TUN
        // descriptor waiting that nothing will adopt. The kill switch goes up
        // first, so nothing slips out while the tunnel is down. As in
        // [releaseBorrowed], `NonCancellable` wraps the lock so a cancel
        // arriving here cannot skip the teardown.
        if (running) {
            withContext(NonCancellable) {
                mutex.withLock {
                    holdBlocker()
                    monitorJob?.cancel()
                    teardown()
                }
            }
        }
        val imported = withContext(Dispatchers.IO) { import(account) }
        if (imported.added + imported.duplicates == 0) {
            warpFail(made, imported.error ?: "the account could not be saved")
            fallbackConnect(asked)
            return
        }
        val key = withContext(Dispatchers.IO) { serverKeyOf(account) }
        if (key == null) {
            warpFail(made, "the account was saved but could not be read back")
            fallbackConnect(asked)
            return
        }
        // The account is a server now, so the connect goes to it and nowhere
        // else: the ladder would move off it and lose the second hop.
        target = ConnectTarget.Specific(key)
        mutex.withLock { runConnection() }
        if (!running) {
            fallbackConnect(asked)
            return
        }
        warp.value = WarpState(WarpPhase.Done, made.steps, made.fingerprint, made.exits, made.route)
    }

    /** Say what went wrong, keeping the steps that led there. */
    private fun warpFail(made: WarpAccount, reason: String) {
        EngineLog.w("warp: $reason")
        warp.value = WarpState(WarpPhase.Failed, made.steps, error = reason)
    }

    /**
     * The connect that was asked for still happens when the setup could not
     * make an account: the setup is an addition to connecting, never a
     * replacement for it. The target is restored either way, because the setup
     * may have pointed it at the account on the way.
     */
    private suspend fun fallbackConnect(asked: ConnectTarget) {
        target = asked
        if (running) return
        EngineLog.i("warp: connecting as usual instead")
        mutex.withLock { runConnection() }
    }

    /**
     * Run the native registration job and wait for its one final answer.
     *
     * The request goes straight out when [quick], with the short deadline the
     * core uses for that, and only the answer matters. Otherwise it goes
     * through the tunnel in hand: the service is filtered by name, so a
     * running proxy is the one path there that always works.
     *
     * The wait is bounded: the job's events only end the flow when a final
     * answer arrives, and a job that never starts sends none. Without a
     * deadline that would hang the setup, and a borrowed tunnel with it.
     */
    private suspend fun registerAccount(quick: Boolean = false): WarpAccount = withContext(Dispatchers.IO) {
        val request = if (quick) JSONObject().put("quick", true) else
            JSONObject().put("direct", false).put("proxy", "127.0.0.1:${settings.httpPort}")
                .put("proxyAuth", LocalProxyAuth.userPass)
        // The servers it looks for depend on the order: reachable through
        // Cloudflare for Reverse, reachable from here for Hybrid, and for
        // Auto the first of those two ways that finds any.
        request.put("order", settings.warpOrder.wire)
        // Long enough for a registration and a search through the feeds, short
        // enough that a stuck job cannot hold a connect open for ever.
        request.put("budget_ms", WARP_BOOT_BUDGET_MS)
        var steps = emptyList<String>()
        var account: String? = null
        var fingerprint = ""
        var exits = 0
        var route = ""
        var error: String? = null
        var unreachable = false
        var finished = false
        val answers = async {
            nativeJob { ZrayNative.warpRegister(request.toString(), it) }.collect { e ->
                when (e.optString("t")) {
                    "step" -> {
                        EngineLog.i("warp: ${e.optString("line")}")
                        steps = (steps + e.optString("line")).takeLast(WARP_STEPS_KEPT)
                        warp.value = WarpState(WarpPhase.Working, steps)
                    }
                    "done" -> {
                        finished = true
                        if (e.optBoolean("ok")) {
                            account = e.optString("link")
                            fingerprint = e.optString("fingerprint")
                            exits = e.optInt("exits")
                            route = e.optString("route")
                        } else {
                            error = e.optString("error").ifBlank { "the WARP service did not answer" }
                            // Only "nothing answered at all" is worth borrowing a
                            // server for.
                            unreachable = e.optBoolean("unreachable")
                        }
                    }
                }
            }
        }
        // Nothing to answer a job that started is a failure, but not an
        // *unreachable* one: borrowing a server for it would change nothing.
        val answered = withTimeoutOrNull(WARP_BOOT_WAIT_MS) { answers.await() }
        if (answered == null) {
            answers.cancel()
            return@withContext WarpAccount(null, steps, "the WARP service did not answer", false)
        }
        if (!finished) error = "cancelled"
        WarpAccount(account, steps, error, unreachable, fingerprint, exits, route)
    }

    /** The store's key for a share link, which is what a specific connect names. */
    private fun serverKeyOf(link: String): String? {
        val items = JSONObject(ZrayNative.parseLinks(link)).optJSONArray("items") ?: return null
        if (items.length() == 0) return null
        return items.getJSONObject(0).optString("key").ifBlank { null }
    }

    /** What one registration attempt ended with. */
    private class WarpAccount(
        val account: String?,
        val steps: List<String>,
        val error: String?,
        val unreachable: Boolean,
        val fingerprint: String = "",
        val exits: Int = 0,
        val route: String = "",
    )

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
        // A panel's heavy JSON variants become its plain link list.
        val body = httpGet(ZrayNative.subscriptionFetchUrl(sub.url).ifEmpty { sub.url })
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

/**
 * The adaptive speed floor for [SpeedFloor.Adaptive]: learn what the user's
 * connection actually delivers and judge the config in use against that,
 * instead of a fixed Mbps that is wrong on both a throttled mobile network and
 * on fibre. Mirrors the Rust reference in `zeronet-tui/src/adaptive_speed.rs`
 * (kept identical so both clients behave the same); see its tests for the
 * rationale of each constant.
 */
internal class AdaptiveFloor {
    private val recent = ArrayDeque<Long>()

    /** Record the best sustained speed (bytes/s) a config reached before it was
     *  left. Near-zero samples say nothing about the network and are ignored. */
    fun record(sustainedBps: Long) {
        if (sustainedBps < MIN_BASELINE_BPS) return
        if (recent.size == HISTORY) recent.removeFirst()
        recent.addLast(sustainedBps)
    }

    /** The learned baseline: the median of recent speeds, once at least two
     *  configs have been seen (one is not a comparison). */
    /** Forget every recorded speed: the network changed. */
    fun clear() = recent.clear()

    fun baseline(): Long? {
        if (recent.size < 2) return null
        val sorted = recent.sorted()
        val mid = sorted.size / 2
        return if (sorted.size % 2 == 0) (sorted[mid - 1] + sorted[mid]) / 2 else sorted[mid]
    }

    /** The floor to compare live throughput against, bytes/s. 0 = do not judge
     *  (too little history, or a network slow enough that everything is near
     *  the baseline anyway). */
    fun effectiveFloorBps(): Long {
        val base = baseline() ?: return 0L
        return if (base >= MIN_BASELINE_BPS) base * SLOW_NUMERATOR / SLOW_DENOMINATOR else 0L
    }

    /** Whether [currentBps] is really slow next to the last two configs: under
     *  the adaptive floor *and* slower than each of the previous two, so one
     *  lucky fast reading does not condemn a config on its own. */
    fun tooSlow(currentBps: Long): Boolean {
        val floor = effectiveFloorBps()
        if (floor == 0L || currentBps >= floor) return false
        val n = recent.size
        return currentBps < recent[n - 1] && currentBps < recent[n - 2]
    }

    private companion object {
        const val HISTORY = 5
        const val SLOW_NUMERATOR = 2L
        const val SLOW_DENOMINATOR = 5L
        const val MIN_BASELINE_BPS = 8_000L
    }
}

/**
 * The sustained download speed of a window of one-second samples, or null when
 * the window was not a bulk transfer: fewer than [minActive] seconds moved real
 * data. The median of the active seconds, so one burst neither makes a config
 * look fast nor a pause make it look slow.
 */
internal fun sustainedDownload(window: List<Long>, minActiveBps: Long = 4_000L, minActive: Int = 10): Long? {
    val active = window.filter { it > minActiveBps }.sorted()
    if (active.size < minActive) return null
    val mid = active.size / 2
    return if (active.size % 2 == 0) (active[mid - 1] + active[mid]) / 2 else active[mid]
}
