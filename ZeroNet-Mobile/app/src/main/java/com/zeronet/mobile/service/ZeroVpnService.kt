package com.zeronet.mobile.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.zeronet.mobile.BuildConfig
import com.zeronet.mobile.R
import com.zeronet.mobile.core.SocketProtection
import com.zeronet.mobile.model.AppFilterMode
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.model.TrafficStats
import com.zeronet.mobile.ui.MainActivity

/**
 * The platform side of the tunnel: foreground service, VPN interface,
 * socket protection, network tracking and the notification.
 *
 * The interface setup follows v2rayNG's CoreVpnService (GPL-3.0; routes that
 * bypass private ranges, the app's own package excluded, per-app filtering),
 * rewritten around Zray, which adopts the TUN descriptor directly instead of
 * running tun2socks.
 */
class ZeroVpnService : VpnService(), TunnelHost {

    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastState: ConnState = ConnState.Idle

    override fun onCreate() {
        super.onCreate()
        SocketProtection.install { fd -> protect(fd) }
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Foreground first: the platform gives a started foreground service
        // only a few seconds to call startForeground, and discovery can take longer.
        startInForeground(buildNotification(Engine.state.value, null))
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                Engine.disconnect()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> Engine.start(this, fromSystem = false)
            // null intent (restart) or SERVICE_INTERFACE (always-on VPN / system)
            else -> {
                if (prepare(this) != null) {
                    stopSelf(); return START_NOT_STICKY
                }
                Engine.start(this, fromSystem = true)
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Engine.onRevoked()
    }

    override fun onDestroy() {
        unregisterNetworkCallback()
        SocketProtection.install(null)
        super.onDestroy()
    }

    // --------------------------------------------------------------- TunnelHost

    override fun establish(settings: Settings): ParcelFileDescriptor? {
        if (prepare(this) != null) return null
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(settings.mtu)
            .addAddress(TUN_V4, 30)
            .addDnsServer(DNS_V4)
        if (settings.bypassLan) {
            ROUTED_V4.forEach { cidr -> cidr.split('/').let { builder.addRoute(it[0], it[1].toInt()) } }
        } else {
            builder.addRoute("0.0.0.0", 0)
        }
        if (settings.ipv6) {
            builder.addAddress(TUN_V6, 126)
            if (settings.bypassLan) builder.addRoute("2000::", 3) else builder.addRoute("::", 0)
        }
        configureApps(builder, settings)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        builder.setConfigureIntent(openAppIntent())
        val pfd = runCatching { builder.establish() }.onFailure { Log.e(TAG, "establish", it) }.getOrNull()
        if (pfd != null) registerNetworkCallback()
        return pfd
    }

    /**
     * The app's own traffic (Zray's sockets, discovery, feed downloads) never
     * enters its own tunnel: excluded in "all"/"all except" mode, simply not
     * listed in "only selected" mode. Protection stays installed as a second
     * guarantee.
     */
    private fun configureApps(builder: Builder, settings: Settings) {
        val self = packageName
        when (settings.appFilter) {
            AppFilterMode.All -> builder.addDisallowedApplication(self)
            AppFilterMode.AllExceptSelected -> {
                builder.addDisallowedApplication(self)
                settings.filteredApps.filter { it != self }.forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (_: PackageManager.NameNotFoundException) {}
                }
            }
            AppFilterMode.OnlySelected -> {
                val apps = settings.filteredApps.filter { it != self }
                if (apps.isEmpty()) {
                    builder.addDisallowedApplication(self)
                } else {
                    apps.forEach { pkg ->
                        try { builder.addAllowedApplication(pkg) } catch (_: PackageManager.NameNotFoundException) {}
                    }
                }
            }
        }
    }

    override fun onStateChanged(state: ConnState) {
        lastState = state
        notifySafely(buildNotification(state, null))
    }

    override fun onStats(stats: TrafficStats) {
        if (lastState is ConnState.Connected) notifySafely(buildNotification(lastState, stats))
    }

    override fun finish() {
        unregisterNetworkCallback()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------ network

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                setUnderlyingNetworks(arrayOf(network))
                Engine.onNetworkChanged()
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                setUnderlyingNetworks(arrayOf(network))
            }

            override fun onLost(network: Network) {
                setUnderlyingNetworks(null)
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching { connectivity.requestNetwork(request, callback) }
            .onSuccess { networkCallback = callback }
            .onFailure { Log.w(TAG, "network callback", it) }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
    }

    // ------------------------------------------------------------ notification

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW).apply {
                    setShowBadge(false)
                    enableVibration(false)
                    setSound(null, null)
                },
            )
        }
    }

    private fun startInForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notifySafely(notification: Notification) {
        runCatching { getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification) }
    }

    private fun buildNotification(state: ConnState, stats: TrafficStats?): Notification {
        val title: String
        val text: String
        when (state) {
            is ConnState.Connected -> {
                title = getString(R.string.notification_connected)
                text = if (stats != null) {
                    "↓ ${formatRate(stats.downRate)}   ↑ ${formatRate(stats.upRate)}"
                } else {
                    state.server.name
                }
            }
            is ConnState.Searching -> {
                title = getString(R.string.notification_searching)
                text = if (state.progress.candidates > 0) {
                    getString(R.string.notification_searching_detail, state.progress.realDone, state.progress.alive)
                } else ""
            }
            is ConnState.Connecting -> { title = getString(R.string.notification_connecting); text = state.server?.name.orEmpty() }
            is ConnState.Reconnecting -> { title = getString(R.string.notification_reconnecting); text = "" }
            else -> { title = getString(R.string.app_name); text = "" }
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this)
        builder.setSmallIcon(R.drawable.ic_tile)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(openAppIntent())
            .addAction(
                Notification.Action.Builder(null, getString(R.string.notification_disconnect), disconnectIntent()).build(),
            )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return builder.build()
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun disconnectIntent(): PendingIntent = PendingIntent.getService(
        this, 1, Intent(this, ZeroVpnService::class.java).setAction(ACTION_DISCONNECT),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    companion object {
        private const val TAG = "ZeroVpn"
        const val ACTION_CONNECT = "${BuildConfig.APPLICATION_ID}.CONNECT"
        const val ACTION_DISCONNECT = "${BuildConfig.APPLICATION_ID}.DISCONNECT"
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1

        /** Must match the tun inbound Zray's buildConfig generates (docs/native-contract.md). */
        const val TUN_V4 = "172.19.0.1"
        const val TUN_V6 = "fdfe:dcba:9876::1"
        /** Queries to this address enter the tunnel and are answered by Zray's DNS. */
        const val DNS_V4 = "1.1.1.1"

        /** Everything except private/link-local/multicast ranges (from v2rayNG's AppConfig). */
        val ROUTED_V4 = listOf(
            "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2",
            "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10",
            "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11",
            "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12",
            "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4",
            "240.0.0.0/4",
        )

        fun formatRate(bytesPerSecond: Long): String = when {
            bytesPerSecond >= 1_000_000 -> String.format(java.util.Locale.US, "%.1f MB/s", bytesPerSecond / 1_000_000.0)
            bytesPerSecond >= 1_000 -> String.format(java.util.Locale.US, "%.0f KB/s", bytesPerSecond / 1_000.0)
            else -> "$bytesPerSecond B/s"
        }

        fun connect(context: Context) {
            val intent = Intent(context, ZeroVpnService::class.java).setAction(ACTION_CONNECT)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}
