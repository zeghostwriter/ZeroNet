package com.zeronet.mobile.ui

import android.app.LocaleManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.LocaleList
import android.provider.Settings as SystemSettings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.zeronet.mobile.data.SettingsStore
import com.zeronet.mobile.model.AppLanguage
import com.zeronet.mobile.model.AutoConnect
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.ui.shell.Tab
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Locale

/**
 * The only activity. It owns what needs an Activity (permission dialogs,
 * ActivityResult, locale switching) and hands everything else to
 * [AppController]; the engine binding lives exactly as long as the UI is
 * visible (onStart/onStop).
 */
class MainActivity : ComponentActivity(), PlatformActions {

    private lateinit var controller: AppController
    private var showOnboarding by mutableStateOf(false)
    private var lastDark: Boolean? = null

    private var vpnCallback: ((Boolean) -> Unit)? = null
    private var notificationCallback: ((Boolean) -> Unit)? = null
    private var localNetworkCallback: ((Boolean) -> Unit)? = null

    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val granted = result.resultCode == RESULT_OK || VpnService.prepare(this) == null
        vpnCallback?.invoke(granted)
        vpnCallback = null
    }
    private val notificationLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationCallback?.invoke(granted)
        notificationCallback = null
    }
    private val localNetworkLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        localNetworkCallback?.invoke(granted)
        localNetworkCallback = null
    }

    // ------------------------------------------------------------ lifecycle

    override fun attachBaseContext(newBase: Context) {
        // Below Android 13 there is no per-app language: wrap the configuration.
        super.attachBaseContext(if (Build.VERSION.SDK_INT < 33) wrapLocale(newBase) else newBase)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        controller = AppController(applicationContext, lifecycleScope, this)
        savedInstanceState?.getString(KEY_TAB)?.let { name -> Tab.entries.firstOrNull { it.name == name }?.let { controller.tab = it } }
        showOnboarding = !uiPrefs().getBoolean(PREF_ONBOARDED, false)
        if (Build.VERSION.SDK_INT >= 33) syncLanguageFromSystem()

        setContent {
            ZeroNetApp(
                controller = controller,
                showOnboarding = showOnboarding,
                onOnboardingFinished = {
                    uiPrefs().edit().putBoolean(PREF_ONBOARDED, true).apply()
                    showOnboarding = false
                },
                onThemeResolved = ::applySystemBars,
            )
        }

        if (savedInstanceState == null) {
            handleIntent(intent)
            maybeAutoConnect()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        controller.engine.attach()
    }

    override fun onStop() {
        controller.engine.detach()
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_TAB, controller.tab.name)
    }

    // ------------------------------------------------------------ intents

    /** Shared text or a tapped vless:// (etc.) link: open Servers with the import sheet prefilled. */
    private fun handleIntent(intent: Intent?) {
        val text = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            Intent.ACTION_VIEW -> intent.dataString
            else -> null
        }?.trim()
        if (text.isNullOrEmpty()) return
        // Links shared from browsers/messengers can be huge; the import sheet only needs text.
        controller.pendingImport = text.take(MAX_IMPORT_CHARS)
        controller.tab = Tab.Servers
    }

    /**
     * "Connect on app start": the engine pushes its real state right after the
     * binding completes, so wait briefly for it before deciding the tunnel is down.
     */
    private fun maybeAutoConnect() {
        if (controller.settings.current.autoConnect != AutoConnect.OnAppStart) return
        lifecycleScope.launch {
            val live = withTimeoutOrNull(AUTO_CONNECT_WAIT_MS) { controller.engine.state.first { it != ConnState.Idle } }
            if (live == null && controller.engine.state.value == ConnState.Idle && !showOnboarding) controller.connect()
        }
    }

    // ------------------------------------------------------------ system bars

    private fun applySystemBars(dark: Boolean) {
        if (lastDark == dark) return
        lastDark = dark
        val style = if (dark) {
            SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        } else {
            SystemBarStyle.light(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT)
        }
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
    }

    // ------------------------------------------------------------ PlatformActions

    override fun requestVpnPermission(onResult: (Boolean) -> Unit) {
        val intent = runCatching { VpnService.prepare(this) }.getOrNull()
        if (intent == null) {
            onResult(true)
            return
        }
        vpnCallback = onResult
        try {
            vpnLauncher.launch(intent)
        } catch (_: ActivityNotFoundException) {
            // Some stripped ROMs have no VPN consent dialog.
            vpnCallback = null
            onResult(false)
        }
    }

    override fun requestNotificationPermission(onResult: (Boolean) -> Unit) {
        requestRuntimePermission(33, android.Manifest.permission.POST_NOTIFICATIONS, onResult) { notificationCallback = it; notificationLauncher }
    }

    override fun requestLocalNetworkPermission(onResult: (Boolean) -> Unit) {
        requestRuntimePermission(37, PERMISSION_LOCAL_NETWORK, onResult) { localNetworkCallback = it; localNetworkLauncher }
    }

    private fun requestRuntimePermission(
        minSdk: Int,
        permission: String,
        onResult: (Boolean) -> Unit,
        register: ((Boolean) -> Unit) -> androidx.activity.result.ActivityResultLauncher<String>,
    ) {
        if (Build.VERSION.SDK_INT < minSdk ||
            ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        ) {
            onResult(true)
            return
        }
        register(onResult).launch(permission)
    }

    override fun openVpnSettings() {
        val opened = runCatching { startActivity(Intent(SystemSettings.ACTION_VPN_SETTINGS)) }.isSuccess
        if (!opened) runCatching { startActivity(Intent(SystemSettings.ACTION_WIRELESS_SETTINGS)) }
    }

    override fun openUrl(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)) }
    }

    override fun applyLanguage(settings: Settings) {
        if (Build.VERSION.SDK_INT >= 33) {
            // The system persists it, recreates the activity and shows it in Settings → Apps → Language.
            getSystemService(LocaleManager::class.java)?.applicationLocales = localeListFor(settings.language)
        } else {
            recreate()
        }
    }

    /** Android 13+: the user may have changed the app language in system settings; follow it. */
    private fun syncLanguageFromSystem() {
        if (Build.VERSION.SDK_INT < 33) return
        val locales = getSystemService(LocaleManager::class.java)?.applicationLocales ?: return
        val system = when {
            locales.isEmpty -> AppLanguage.System
            locales[0].language == "fa" -> AppLanguage.Persian
            else -> AppLanguage.English
        }
        val store = SettingsStore.get(this)
        if (store.current.language != system) store.update { it.copy(language = system) }
    }

    private fun uiPrefs() = getSharedPreferences(PREFS_UI, MODE_PRIVATE)

    companion object {
        private const val PREFS_UI = "ui"
        private const val PREF_ONBOARDED = "onboarded"
        private const val KEY_TAB = "tab"
        private const val PERMISSION_LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
        private const val AUTO_CONNECT_WAIT_MS = 1_200L
        private const val MAX_IMPORT_CHARS = 512 * 1024

        private fun localeFor(language: AppLanguage): Locale? = when (language) {
            AppLanguage.System -> null
            AppLanguage.English -> Locale.ENGLISH
            AppLanguage.Persian -> Locale.forLanguageTag("fa")
        }

        private fun localeListFor(language: AppLanguage): LocaleList =
            localeFor(language)?.let { LocaleList(it) } ?: LocaleList.getEmptyLocaleList()

        /** Pre-13 per-app language: a configuration override on the activity's base context. */
        private fun wrapLocale(base: Context): Context {
            val language = runCatching { SettingsStore.get(base).current.language }.getOrDefault(AppLanguage.System)
            val locale = localeFor(language) ?: return base
            val config = Configuration(base.resources.configuration)
            config.setLocale(locale)
            config.setLayoutDirection(locale)
            return base.createConfigurationContext(config)
        }
    }
}
