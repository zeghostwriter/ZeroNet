package com.zeronet.mobile.ui.settings

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zeronet.mobile.BuildConfig
import com.zeronet.mobile.R
import com.zeronet.mobile.data.LanAddresses
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.ui.LocalController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Which settings only take effect on the next connect (everything else the engine applies live). */
private val RECONNECT_FIELDS: Map<SettingsCardId, (Settings) -> Any> = mapOf(
    SettingsCardId.Connection to { s -> listOf(s.mode, s.ipv6, s.mtu) },
    SettingsCardId.Split to { s -> listOf(s.appFilter, s.filteredApps, s.bypassLan) },
)

@Composable
fun SettingsRoute() {
    val controller = LocalController.current
    val resources = androidx.compose.ui.platform.LocalResources.current
    val settings by controller.settings.settings.collectAsStateWithLifecycle()
    val conn by controller.engine.state.collectAsStateWithLifecycle()
    val servers by controller.servers.servers.collectAsStateWithLifecycle()
    val subscriptions by controller.servers.subscriptions.collectAsStateWithLifecycle()
    var lanDenied by rememberSaveable { mutableStateOf(false) }

    val connected = conn is ConnState.Connected
    // Read connectedWith so the reconnect chips follow the connection snapshot.
    val snapshot = controller.connectedWith
    val reconnectCards = remember(settings, snapshot, connected) {
        RECONNECT_FIELDS.filter { (_, select) -> controller.needsReconnect(settings, select) }.keys
    }
    val derived by produceState(Triple(emptyList<String>(), 0, emptyList<String>()), servers) {
        value = withContext(Dispatchers.Default) {
            val countries = servers.asSequence().map { it.country }.filter { it.length == 2 }.distinct().toList()
            val discovered = servers.filterNot { it.isUser }
            Triple(countries, discovered.size, discovered.map { it.key })
        }
    }
    val lanAddresses = rememberLanAddresses(settings.lanShare)
    val update by controller.updater.state.collectAsStateWithLifecycle()

    SettingsScreen(
        state = SettingsUiState(
            settings = settings,
            connected = connected,
            reconnectCards = reconnectCards,
            subscriptions = subscriptions,
            knownCountries = derived.first,
            discoveredCount = derived.second,
            lanAddresses = lanAddresses,
            lanPermissionDenied = lanDenied,
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            update = update,
        ),
        actions = remember(controller, derived) {
            SettingsActions(
                onChange = controller::update,
                onReconnect = { controller.reconnect() },
                onLanShare = { on ->
                    if (!on) {
                        controller.update { it.copy(lanShare = false) }
                    } else {
                        controller.platform.requestLocalNetworkPermission { granted ->
                            lanDenied = !granted
                            if (granted) controller.update { it.copy(lanShare = true) }
                        }
                    }
                },
                onOpenVpnSettings = controller.platform::openVpnSettings,
                onAddSubscription = { name, url ->
                    controller.engine.addSubscription(name, url)
                    controller.messages.show(resources.getString(R.string.msg_subscription_added))
                },
                onRemoveSubscription = { controller.engine.removeSubscription(it.id) },
                onClearHistory = {
                    controller.servers.delete(derived.third)
                    controller.messages.show(resources.getString(R.string.msg_history_cleared))
                },
                onCopy = { text -> controller.copy(text, sensitive = text.contains('@')) },
                onUpdates = controller::openUpdates,
            )
        },
    )
}

/**
 * The phone's shareable LAN addresses, re-read whenever the default network
 * changes while sharing is on (joining Wi-Fi, starting the hotspot…).
 */
@Composable
private fun rememberLanAddresses(enabled: Boolean): List<String> {
    val context = LocalContext.current
    var generation by remember { mutableIntStateOf(0) }
    DisposableEffect(enabled, context) {
        if (!enabled) return@DisposableEffect onDispose { }
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { generation++ }
            override fun onLost(network: Network) { generation++ }
            override fun onLinkPropertiesChanged(network: Network, lp: android.net.LinkProperties) { generation++ }
        }
        val registered = cm != null && runCatching { cm.registerDefaultNetworkCallback(callback) }.isSuccess
        onDispose { if (registered) runCatching { cm.unregisterNetworkCallback(callback) } }
    }
    val addresses by produceState(emptyList<String>(), enabled, generation) {
        value = if (enabled) withContext(Dispatchers.IO) { LanAddresses.list() } else emptyList()
    }
    return addresses
}
