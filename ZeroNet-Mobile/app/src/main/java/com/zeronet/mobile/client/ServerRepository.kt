package com.zeronet.mobile.client

import android.content.Context
import com.zeronet.mobile.data.ServerStore
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.Server
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * The server list as the UI sees it: read from the shared SQLite store off the
 * main thread, re-read whenever the engine says it changed.
 */
class ServerRepository private constructor(context: Context) {
    private val store = ServerStore.get(context)
    private val client = EngineClient.get(context)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _servers = MutableStateFlow<List<Server>>(emptyList())
    val servers: StateFlow<List<Server>> = _servers.asStateFlow()

    private val _subscriptions = MutableStateFlow<List<Subscription>>(emptyList())
    val subscriptions: StateFlow<List<Subscription>> = _subscriptions.asStateFlow()

    init {
        reload()
        scope.launch { client.serversChanged.collect { reload() } }
    }

    fun reload() {
        scope.launch {
            _servers.value = store.all()
            _subscriptions.value = store.subscriptions()
        }
    }

    fun setFavorite(key: String, favorite: Boolean) {
        scope.launch {
            store.setFavorite(key, favorite)
            _servers.value = store.all()
        }
    }

    fun delete(keys: Collection<String>) {
        scope.launch {
            store.delete(keys)
            _servers.value = store.all()
        }
    }

    companion object {
        @Volatile private var instance: ServerRepository? = null
        fun get(context: Context): ServerRepository =
            instance ?: synchronized(this) { instance ?: ServerRepository(context.applicationContext).also { instance = it } }
    }
}
