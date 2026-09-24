package com.zeronet.mobile.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import com.zeronet.mobile.data.SettingsStore
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ImportResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.TrafficStats
import com.zeronet.mobile.service.EngineService
import com.zeronet.mobile.service.Ipc
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject

/**
 * The UI process's handle on the engine in the :vpn process.
 *
 * Bind with [attach] while the UI is visible and [detach] when it is not:
 * the engine only pushes stats to registered clients, so a detached UI costs
 * nothing. Commands issued before the binding completes are queued.
 */
class EngineClient private constructor(private val context: Context) {

    private val _state = MutableStateFlow<ConnState>(ConnState.Idle)
    val state: StateFlow<ConnState> = _state.asStateFlow()

    private val _stats = MutableStateFlow(TrafficStats())
    val stats: StateFlow<TrafficStats> = _stats.asStateFlow()

    private val _scan = MutableStateFlow(ScanState())
    val scan: StateFlow<ScanState> = _scan.asStateFlow()

    /** Background refresh (Servers pull-to-refresh / test all): true while running. */
    private val _refreshing = MutableStateFlow(false)
    val refreshing: StateFlow<Boolean> = _refreshing.asStateFlow()

    /** (done, total) of the current test-all run, or null. */
    private val _testProgress = MutableStateFlow<Pair<Int, Int>?>(null)
    val testProgress: StateFlow<Pair<Int, Int>?> = _testProgress.asStateFlow()

    /** Emits whenever the server table changed in the :vpn process. */
    private val _serversChanged = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    val serversChanged: SharedFlow<Unit> = _serversChanged.asSharedFlow()

    private val main = Handler(Looper.getMainLooper())
    private val incoming = Messenger(IncomingHandler())
    private var service: Messenger? = null
    private var bound = false
    private val pending = ArrayList<Message>()
    private var pendingImport: CompletableDeferred<ImportResult>? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = Messenger(binder)
            send(Ipc.REGISTER, null)
            val queued = ArrayList(pending)
            pending.clear()
            queued.forEach { dispatch(it) }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            // The :vpn process died. The tunnel is gone with it.
            service = null
            _state.value = ConnState.Idle
            _refreshing.value = false
        }
    }

    fun attach() {
        if (bound) return
        bound = context.bindService(Intent(context, EngineService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    fun detach() {
        if (!bound) return
        send(Ipc.UNREGISTER, null)
        runCatching { context.unbindService(connection) }
        bound = false
        service = null
    }

    // --------------------------------------------------------------- commands

    /** VPN permission must already be granted when mode is VPN (see VpnService.prepare). */
    fun connect(target: ConnectTarget) {
        val settings = SettingsStore.get(context).current
        send(Ipc.CONNECT, JSONObject().put("target", target.encode()).put("settings", settings.toJson()).toString())
    }

    fun disconnect() = send(Ipc.DISCONNECT, null)

    /** Real-delay test of the given servers (or all stored ones when empty). */
    fun test(keys: Collection<String> = emptyList()) = send(Ipc.TEST, JSONArray(keys.toList()).toString())

    /** Run discovery in the background to refill the server list, without connecting. */
    fun refresh() {
        val settings = SettingsStore.get(context).current
        send(Ipc.REFRESH, settings.toJson().toString())
    }

    fun startScan(count: Int = 2000) = send(Ipc.SCAN_START, JSONObject().put("count", count).toString())
    fun stopScan() = send(Ipc.SCAN_STOP, null)

    /** Tell the engine settings changed (applies LAN/routing changes to a live connection). */
    fun pushSettings() = send(Ipc.SETTINGS, SettingsStore.get(context).current.toJson().toString())

    fun addSubscription(name: String, url: String) =
        send(Ipc.ADD_SUBSCRIPTION, JSONObject().put("name", name).put("url", url).toString())

    fun removeSubscription(id: String) = send(Ipc.REMOVE_SUBSCRIPTION, id)

    /** Import links / subscription text. Suspends until the engine parsed it (max 10 s). */
    suspend fun import(text: String): ImportResult {
        val deferred = CompletableDeferred<ImportResult>()
        pendingImport?.cancel()
        pendingImport = deferred
        send(Ipc.IMPORT, text)
        return withTimeoutOrNull(10_000) { deferred.await() }
            ?: ImportResult(0, 0, 0, "The engine did not answer in time")
    }

    // --------------------------------------------------------------- plumbing

    private fun send(what: Int, json: String?) {
        val msg = Message.obtain(null, what).apply {
            replyTo = incoming
            if (json != null) data = Bundle(1).apply { putString(Ipc.KEY, json) }
        }
        if (service == null) {
            if (what != Ipc.UNREGISTER && what != Ipc.REGISTER) pending += msg
            attach()
            return
        }
        dispatch(msg)
    }

    private fun dispatch(msg: Message) {
        try {
            service?.send(msg) ?: pending.add(msg)
        } catch (_: RemoteException) {
            service = null
        }
    }

    private inner class IncomingHandler : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            val json = msg.data?.getString(Ipc.KEY)
            when (msg.what) {
                Ipc.STATE -> json?.let { _state.value = Ipc.stateFromJson(it) }
                Ipc.STATS -> json?.let { _stats.value = Ipc.statsFromJson(it) }
                Ipc.SCAN -> json?.let { _scan.value = Ipc.scanFromJson(it) }
                Ipc.SERVERS_CHANGED -> _serversChanged.tryEmit(Unit)
                Ipc.REFRESH_STATE -> _refreshing.value = json == "1"
                Ipc.TEST_PROGRESS -> _testProgress.value = json?.let {
                    val o = JSONObject(it)
                    if (o.optBoolean("done")) null else o.optInt("d") to o.optInt("t")
                }
                Ipc.IMPORT_RESULT -> json?.let { pendingImport?.complete(Ipc.importFromJson(it)); pendingImport = null }
            }
        }
    }

    companion object {
        @Volatile private var instance: EngineClient? = null
        fun get(context: Context): EngineClient =
            instance ?: synchronized(this) { instance ?: EngineClient(context.applicationContext).also { instance = it } }
    }
}
