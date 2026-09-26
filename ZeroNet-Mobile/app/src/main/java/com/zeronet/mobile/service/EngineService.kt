package com.zeronet.mobile.service

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.model.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * The UI's entry point into the :vpn process: a bound Messenger service.
 *
 * It relays commands to [Engine] and pushes the engine's state to every
 * registered client. Stats are only forwarded while at least one client is
 * registered, so a backgrounded UI costs nothing.
 */
class EngineService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val clientsList = ArrayList<Messenger>()
    private val messenger = Messenger(IncomingHandler())
    private var forwarding: Job? = null

    override fun onBind(intent: Intent?): IBinder = messenger.binder

    override fun onDestroy() {
        scope.cancel()
        Engine.clients.set(0)
        super.onDestroy()
    }

    private fun startForwarding() {
        if (forwarding != null) return
        forwarding = scope.launch {
            launch { Engine.state.collect { broadcast(Ipc.STATE, Ipc.stateToJson(it)) } }
            launch { Engine.stats.drop(1).collect { broadcast(Ipc.STATS, Ipc.statsToJson(it)) } }
            launch { Engine.scan.collect { broadcast(Ipc.SCAN, Ipc.scanToJson(it)) } }
            launch { Engine.refreshing.collect { broadcast(Ipc.REFRESH_STATE, if (it) "1" else "0") } }
            launch {
                Engine.testProgress.collect { p ->
                    val o = if (p == null) JSONObject().put("done", true) else JSONObject().put("d", p.first).put("t", p.second)
                    broadcast(Ipc.TEST_PROGRESS, o.toString())
                }
            }
            launch { Engine.serversChanged.collect { broadcast(Ipc.SERVERS_CHANGED, null) } }
            launch { Engine.diagnosis.collect { broadcast(Ipc.DIAGNOSIS, Ipc.diagnosisToJson(it)) } }
        }
    }

    private fun broadcast(what: Int, json: String?) {
        val iterator = clientsList.iterator()
        while (iterator.hasNext()) {
            val client = iterator.next()
            try {
                client.send(Message.obtain(null, what).apply {
                    if (json != null) data = Bundle(1).apply { putString(Ipc.KEY, json) }
                })
            } catch (_: RemoteException) {
                iterator.remove()
                Engine.clients.set(clientsList.size)
            }
        }
    }

    private fun reply(to: Messenger?, what: Int, json: String) {
        try {
            to?.send(Message.obtain(null, what).apply { data = Bundle(1).apply { putString(Ipc.KEY, json) } })
        } catch (_: RemoteException) {
        }
    }

    private inner class IncomingHandler : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            val json = msg.data?.getString(Ipc.KEY)
            when (msg.what) {
                Ipc.REGISTER -> msg.replyTo?.let { client ->
                    if (clientsList.none { it.binder == client.binder }) clientsList += client
                    Engine.clients.set(clientsList.size)
                    startForwarding()
                    // Bring the new client up to date immediately.
                    reply(client, Ipc.STATE, Ipc.stateToJson(Engine.state.value))
                    reply(client, Ipc.SCAN, Ipc.scanToJson(Engine.scan.value))
                }
                Ipc.UNREGISTER -> msg.replyTo?.let { client ->
                    clientsList.removeAll { it.binder == client.binder }
                    Engine.clients.set(clientsList.size)
                }
                Ipc.CONNECT -> json?.let {
                    val o = JSONObject(it)
                    val settings = Settings.fromJson(o.getJSONObject("settings"))
                    Engine.prepare(ConnectTarget.decode(o.optString("target")), settings)
                    if (settings.mode == ConnectionMode.Vpn || settings.mode == ConnectionMode.Proxy) {
                        ZeroVpnService.connect(this@EngineService)
                    }
                }
                Ipc.DISCONNECT -> Engine.disconnect()
                Ipc.TEST -> {
                    val keys = json?.let { s -> JSONArray(s).let { a -> List(a.length()) { a.getString(it) } } }.orEmpty()
                    Engine.test(keys)
                }
                Ipc.REFRESH -> json?.let { Engine.refresh(Settings.fromJson(JSONObject(it))) }
                Ipc.SETTINGS -> json?.let { Engine.applySettings(Settings.fromJson(JSONObject(it))) }
                Ipc.SCAN_START -> Engine.startScan(json?.let { JSONObject(it).optInt("count", 2000) } ?: 2000)
                Ipc.SCAN_STOP -> Engine.stopScan()
                Ipc.DIAGNOSE -> Engine.diagnose()
                Ipc.IMPORT -> {
                    val replyTo = msg.replyTo
                    val text = json.orEmpty()
                    scope.launch(Dispatchers.IO) {
                        val result = runCatching { Engine.import(text) }
                            .getOrElse { com.zeronet.mobile.model.ImportResult(0, 0, 0, it.message) }
                        launch(Dispatchers.Main) { reply(replyTo, Ipc.IMPORT_RESULT, Ipc.importToJson(result)) }
                    }
                }
                Ipc.ADD_SUBSCRIPTION -> json?.let {
                    val o = JSONObject(it)
                    val replyTo = msg.replyTo
                    scope.launch(Dispatchers.IO) {
                        val result = runCatching { Engine.addSubscription(o.optString("name"), o.optString("url")) }
                            .getOrElse { com.zeronet.mobile.model.ImportResult(0, 0, 0, it.message) }
                        launch(Dispatchers.Main) { reply(replyTo, Ipc.IMPORT_RESULT, Ipc.importToJson(result)) }
                    }
                }
                Ipc.REMOVE_SUBSCRIPTION -> json?.let { id -> scope.launch(Dispatchers.IO) { Engine.removeSubscription(id) } }
            }
        }
    }
}
