package com.zeronet.mobile.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.zeronet.mobile.model.AutoConnect
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode

/**
 * Auto-connect after boot, when the user chose it and the VPN permission is
 * still granted. (Android's own always-on VPN is the stronger option and is
 * offered in Settings; this covers users who prefer not to lock down.)
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val settings = Engine.snapshotSettings()
        if (settings.autoConnect != AutoConnect.OnBoot) return
        if (settings.mode == ConnectionMode.Vpn && VpnService.prepare(context) != null) return
        Engine.prepare(ConnectTarget.decode(settings.lastTarget), settings)
        runCatching { ZeroVpnService.connect(context) }
    }
}
