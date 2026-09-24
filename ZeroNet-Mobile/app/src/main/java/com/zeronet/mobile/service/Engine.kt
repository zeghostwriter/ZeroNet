package com.zeronet.mobile.service

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.zeronet.mobile.core.ZrayNative
import com.zeronet.mobile.data.NetworkIdentity
import com.zeronet.mobile.data.ServerStore
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.ConnState
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
    private fun suits(server: Server, p: ConnectionProfile): Boolean = when (p) {
        ConnectionProfile.Normal -> server.security == "tls" || server.security == "reality" ||
            server.protocol == "hysteria2" || server.protocol == "tuic"
        ConnectionProfile.Fast -> true
        ConnectionProfile.Gaming -> server.kind != com.zeronet.mobile.model.ServerKind.Cdn &&
            server.transport !in setOf("ws", "httpupgrade", "xhttp", "splithttp")
    }
    private const val HEALTH_INTERVAL_MS = 45_000L
    /** When every server fails a health check, test again this much later before believing it. */
    private const val HEALTH_RETEST_MS = 3_000L
    /** Failed health checks in a row before a chosen config is reported as not answering. */
    private const val CHOSEN_DOWN_AFTER = 2
    /** Test timeout for the user's own configs; see [testServers]. */
    private const val OWN_TIMEOUT_MS = 10_000
    private const val PROBE_URL = "http://cp.cloudflare.com/generate_204"

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

    @Volatile private var settings = Settings()
    @Volatile private var target: ConnectTarget = ConnectTarget.Fastest
    @Volatile private var running = false

    /** Working configs currently behind the balancer, fastest first. */
    private val pool = ArrayList<Alive>()
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
        nativeError = runCatching { ZrayNative.init(app.filesDir.absolutePath, "warn") }
            .fold({ it }, { "native library failed to load: ${it.message}" })
        if (nativeError != null) Log.e(TAG, "native init: $nativeError")
    }

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
            // A failed attempt must not leave a foreground service and its
            // notification behind; the UI shows the failure.
            if (!running && state.value is ConnState.Failed) {
                this@Engine.host?.finish()
                this@Engine.host = null
            }
        }
    }

    fun disconnect() {
        connectJob?.cancel()
        monitorJob?.cancel()
        scope.launch {
            mutex.withLock {
                publish(ConnState.Disconnecting)
                teardown()
                publish(ConnState.Idle)
            }
            host?.finish()
            host = null
        }
    }

    /** Another VPN took over, or the user revoked the permission in system settings. */
    fun onRevoked() {
        connectJob?.cancel()
        monitorJob?.cancel()
        scope.launch {
            mutex.withLock {
                teardown()
                publish(ConnState.Failed(FailReason.VpnRevoked, ""))
            }
            host?.finish()
            host = null
        }
    }

    /** The default network changed (Wi-Fi ↔ cellular, reconnect). */
    fun onNetworkChanged() {
        if (!running) return
        runCatching { ZrayNative.networkChanged() }
        // Checked inside the monitor loop so a disconnect cancels it with the loop.
        healthNow.trySend(Unit)
    }

    /** Settings changed in the UI; apply what can be applied live. */
    fun applySettings(next: Settings) {
        val previous = settings
        settings = next
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
                withContext(NonCancellable) { teardown() }
                runConnection()
            }
            if (!running && state.value is ConnState.Failed) {
                this@Engine.host?.finish()
                this@Engine.host = null
            }
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
        withContext(NonCancellable) {
            ZrayNative.stop()?.let { Log.w(TAG, "restart stop: $it") }
            running = false
            val keepSince = since
            if (bringUpAtomically()) since = keepSince
        }
        publishConnected()
    }

    private suspend fun runConnection() {
        pool.clear()
        chosenFailures = 0
        publish(ConnState.Searching(DiscoveryProgress()))
        if (nativeError != null) {
            fail(FailReason.CoreError, nativeError.orEmpty()); return
        }
        val network = NetworkIdentity.current(app)
        if (network == null) {
            fail(FailReason.NoNetwork, ""); return
        }
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
                    discover(network, excludeKeys = emptySet())
                    if (!running) { fail(FailReason.NoWorkingServer, ""); return }
                }
            }
            monitorJob = scope.launch { monitor(network) }
        } catch (e: BringUpFailed) {
            // bringUp() already published the failure.
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            Log.e(TAG, "connection failed", e)
            teardown()
            fail(FailReason.CoreError, e.message.orEmpty())
        }
    }

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
                    withContext(Dispatchers.IO) {
                        store.upsert(listOf(server))
                        store.recordResult(server.key, delay, network)
                    }
                    serversChanged.tryEmit(Unit)
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
                "error" -> Log.w(TAG, "discovery: ${e.optString("message")}")
                "done" -> if (pendingReload && running) { reloadPool(); pendingReload = false }
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
            nativeJob { ZrayNative.testLinks(request.toString(), it) }.collect { e ->
                if (e.optString("t") != "result") return@collect
                onResult(e.optString("key"), e.optInt("delay_ms", -1), e.optString("error").ifBlank { null })
            }
        }
    }

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
        publishConnected()
        return true
    }

    private suspend fun reloadPool() {
        if (!running || pool.isEmpty()) return
        val config = buildConfig(failOnError = false) ?: return
        val error = withContext(Dispatchers.IO) { ZrayNative.reload(config) }
        if (error != null) {
            Log.w(TAG, "reload refused, restarting: $error")
            restartCore()
            return
        }
        publishConnected()
    }

    private fun buildConfig(failOnError: Boolean = true): String? {
        val s = settings
        val request = JSONObject()
            .put("links", JSONArray(pool.take(linksInConfig(s.profile)).map { it.server.link }))
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
            .put("clean_ips", JSONArray(scan.value.results.take(10).map { "${it.ip}:${it.port}" }))
            .put("log_level", if (s.logs) "info" else "warning")
        val result = JSONObject(ZrayNative.buildConfig(request.toString()))
        if (result.has("error")) {
            Log.e(TAG, "buildConfig: ${result.optString("error")}")
            if (failOnError) fail(FailReason.CoreError, result.optString("error"))
            return null
        }
        return result.getJSONObject("config").toString()
    }

    private fun publishConnected() {
        val best = pool.firstOrNull() ?: return
        publish(ConnState.Connected(best.server, since, best.delayMs, pool.size))
    }

    // ---------------------------------------------------------- health & stats

    private suspend fun monitor(network: String) {
        var lastUp = 0L
        var lastDown = 0L
        val downHistory = ArrayDeque<Long>(60)
        val upHistory = ArrayDeque<Long>(60)
        var tick = 0L
        val power = app.getSystemService(PowerManager::class.java)
        while (currentCoroutineContext().isActive && running) {
            // Sleep one second, or less when a network change asks for a health check now.
            val forced = withTimeoutOrNull(1000) { healthNow.receive() } != null
            tick++
            val interactive = power?.isInteractive ?: true
            if (clients.get() > 0 || interactive) {
                val raw = ZrayNative.stats()
                if (raw != null) {
                    val o = JSONObject(raw)
                    val up = o.optLong("up")
                    val down = o.optLong("down")
                    val upRate = (up - lastUp).coerceAtLeast(0)
                    val downRate = (down - lastDown).coerceAtLeast(0)
                    lastUp = up; lastDown = down
                    if (downHistory.size == 60) downHistory.removeFirst()
                    if (upHistory.size == 60) upHistory.removeFirst()
                    downHistory.addLast(downRate); upHistory.addLast(upRate)
                    val next = TrafficStats(upRate, downRate, up, down, downHistory.toList(), upHistory.toList())
                    stats.value = next
                    if (interactive && tick % 2 == 0L) host?.onStats(next)
                }
            }
            if (forced || (settings.autoSwitch && tick * 1000 % HEALTH_INTERVAL_MS == 0L)) {
                healthCheck(NetworkIdentity.current(app) ?: network)
            }
        }
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
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    // ---------------------------------------------------------------- helpers

    private fun teardown() {
        if (running || ZrayNative.isRunning()) {
            ZrayNative.stop()?.let { Log.w(TAG, "stop: $it") }
        }
        running = false
        pool.clear()
        stats.value = TrafficStats()
    }

    private fun fail(reason: FailReason, detail: String) {
        publish(ConnState.Failed(reason, detail))
    }

    private fun publish(next: ConnState) {
        state.value = next
        host?.onStateChanged(next)
    }

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
