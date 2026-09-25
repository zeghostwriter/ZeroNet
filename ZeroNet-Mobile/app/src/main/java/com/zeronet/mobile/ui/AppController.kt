package com.zeronet.mobile.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.PersistableBundle
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import com.zeronet.mobile.R
import com.zeronet.mobile.client.EngineClient
import com.zeronet.mobile.client.ServerRepository
import com.zeronet.mobile.data.SettingsStore
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.ui.shell.AppMessages
import com.zeronet.mobile.ui.shell.Tab
import com.zeronet.mobile.update.AppUpdater
import com.zeronet.mobile.update.UpdateState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** What the activity does on the controller's behalf (permission dialogs need an Activity). */
interface PlatformActions {
    /** Ask for VPN permission (VpnService.prepare); [onResult] gets true when granted. */
    fun requestVpnPermission(onResult: (Boolean) -> Unit)

    /** POST_NOTIFICATIONS on API 33+; no-op below. */
    fun requestNotificationPermission(onResult: (Boolean) -> Unit)

    /** ACCESS_LOCAL_NETWORK on API 37+; granted immediately below. */
    fun requestLocalNetworkPermission(onResult: (Boolean) -> Unit)

    fun openVpnSettings()

    /** Start a system screen or another app; false if nothing handles it. */
    fun startIntent(intent: android.content.Intent): Boolean
    fun openUrl(url: String)
    fun applyLanguage(settings: Settings)
}

/**
 * The UI's single entry point to the engine, the server store and settings.
 * Screens stay stateless; routes read flows from here and call its actions.
 */
@Stable
class AppController(
    private val context: Context,
    private val scope: CoroutineScope,
    val platform: PlatformActions,
) {
    val engine: EngineClient = EngineClient.get(context)
    val servers: ServerRepository = ServerRepository.get(context)
    val settings: SettingsStore = SettingsStore.get(context)
    val messages = AppMessages()
    val updater: AppUpdater = AppUpdater.get(context)

    /** Whether the update sheet is showing. */
    var updateSheetOpen by mutableStateOf(false)

    /** A manual check opens the sheet with whatever it finds; the start-up check only for new news. */
    private var showNextFinding = false

    /** The user was sent to allow installs; install once they are back. */
    private var pendingInstall = false

    /** Text shared into the app or opened as a link; the Servers tab shows it in the import sheet. */
    var pendingImport by mutableStateOf<String?>(null)

    var tab by mutableStateOf(Tab.Home)

    /** Settings as they were when the current connection came up; null while disconnected. */
    var connectedWith by mutableStateOf<Settings?>(null)
        private set

    init {
        // The app is excluded from its own VPN: while connected, updates
        // come through the local proxy, which GitHub filtering cannot see.
        updater.proxyPort = {
            if (engine.state.value is ConnState.Connected) settings.current.httpPort else null
        }
        scope.launch {
            updater.state.collect { s ->
                when (s) {
                    is UpdateState.Available -> if (showNextFinding || s.release.version != updater.dismissedVersion) {
                        updateSheetOpen = true
                    }
                    is UpdateState.UpToDate -> if (showNextFinding) messages.show(context.getString(R.string.settings_update_latest))
                    is UpdateState.CheckFailed -> if (showNextFinding) messages.show(context.getString(R.string.settings_update_failed, s.message))
                    else -> {}
                }
                if (s !is UpdateState.Checking && s !is UpdateState.Idle) showNextFinding = false
            }
        }
        updater.checkOnStart()
        scope.launch {
            engine.state.collect { s ->
                when {
                    s is ConnState.Connected && connectedWith == null -> connectedWith = settings.current
                    s == ConnState.Idle || s is ConnState.Failed -> connectedWith = null
                }
            }
        }
    }

    // ------------------------------------------------------------ connection

    /** The orb: connect when idle/failed, disconnect otherwise. */
    fun toggle() {
        if (engine.state.value.isActive) engine.disconnect() else connect()
    }

    fun connect(target: ConnectTarget = ConnectTarget.decode(settings.current.lastTarget)) {
        if (settings.current.mode == ConnectionMode.Vpn && needsVpnPermission()) {
            platform.requestVpnPermission { granted ->
                if (granted) engine.connect(target) else messages.show(context.getString(R.string.msg_vpn_permission_denied))
            }
        } else {
            engine.connect(target)
        }
    }

    /** Pick a target (from the picker, a country or a server row): remember it and connect. */
    fun selectTarget(target: ConnectTarget) {
        settings.update { it.copy(lastTarget = target.encode()) }
        if (engine.state.value.isActive) {
            reconnect(target)
        } else {
            connect(target)
        }
    }

    private var reconnectJob: Job? = null

    /** Disconnect, wait for the tunnel to go down, and connect again with current settings. */
    fun reconnect(target: ConnectTarget = ConnectTarget.decode(settings.current.lastTarget)) {
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            if (engine.state.value.isActive) {
                engine.disconnect()
                withTimeoutOrNull(8_000) { engine.state.first { !it.isActive && it != ConnState.Disconnecting } }
            }
            connectedWith = null
            connect(target)
        }
    }

    fun needsVpnPermission(): Boolean = runCatching { VpnService.prepare(context) != null }.getOrDefault(false)

    // ------------------------------------------------------------ updates

    /** Settings → Updates: check now, or reopen the update in progress. */
    fun openUpdates() {
        when (updater.state.value) {
            is UpdateState.Idle, is UpdateState.UpToDate, is UpdateState.CheckFailed -> {
                showNextFinding = true
                updater.check()
            }
            is UpdateState.Checking -> showNextFinding = true
            else -> updateSheetOpen = true
        }
    }

    /** "Later": close the sheet, and don't offer this version again on start. */
    fun dismissUpdate() {
        (updater.state.value as? UpdateState.Available)?.let { updater.dismissedVersion = it.release.version }
        updateSheetOpen = false
    }

    fun installUpdate() {
        if (!updater.canInstall()) {
            pendingInstall = true
            if (!platform.startIntent(updater.installPermissionIntent())) pendingInstall = false
            return
        }
        updater.installIntent()?.let { platform.startIntent(it) }
    }

    fun resumePendingInstall() {
        if (pendingInstall && updater.canInstall()) {
            pendingInstall = false
            updater.installIntent()?.let { platform.startIntent(it) }
        }
    }

    // ------------------------------------------------------------ settings

    /** Apply a settings change immediately and tell the engine. */
    fun update(transform: (Settings) -> Settings) {
        val before = settings.current
        settings.update(transform)
        val after = settings.current
        if (before != after) {
            engine.pushSettings()
            if (before.language != after.language) platform.applyLanguage(after)
        }
    }

    /**
     * Whether a connection is up and was made with different values for the
     * fields [select] picks: those changes only take effect on reconnect.
     */
    fun needsReconnect(current: Settings, select: (Settings) -> Any): Boolean {
        val snapshot = connectedWith ?: return false
        if (engine.state.value !is ConnState.Connected) return false
        return select(snapshot) != select(current)
    }

    // ------------------------------------------------------------ utilities

    fun copy(text: String, sensitive: Boolean = false) {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(context.getString(R.string.app_name), text)
        if (sensitive && Build.VERSION.SDK_INT >= 24) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(if (Build.VERSION.SDK_INT >= 33) android.content.ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)
        // Android 13+ shows its own clipboard confirmation.
        if (Build.VERSION.SDK_INT < 33) messages.show(context.getString(R.string.msg_copied))
    }

    fun readClipboard(): String {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return ""
        val clip = cm.primaryClip ?: return ""
        if (clip.itemCount == 0) return ""
        return clip.getItemAt(0).coerceToText(context)?.toString().orEmpty()
    }
}

val LocalController = staticCompositionLocalOf<AppController> { error("No AppController provided") }
