package com.zeronet.mobile.service

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Quick-settings toggle. Lives in :vpn so it talks to the engine directly. */
class QuickTileService : TileService() {
    private var scope: CoroutineScope? = null
    private var watcher: Job? = null

    override fun onStartListening() {
        val s = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        scope = s
        watcher = s.launch { Engine.state.collect { render(it) } }
    }

    override fun onStopListening() {
        watcher?.cancel()
        scope?.cancel()
        scope = null
    }

    override fun onClick() {
        if (Engine.state.value.isActive) {
            Engine.disconnect()
            return
        }
        val settings = Engine.snapshotSettings()
        if (settings.mode == ConnectionMode.Vpn && VpnService.prepare(this) != null) {
            // Permission is needed: open the app, which asks for it.
            val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
            return
        }
        Engine.prepare(ConnectTarget.decode(settings.lastTarget), settings)
        ZeroVpnService.connect(this)
    }

    private fun render(state: ConnState) {
        val tile = qsTile ?: return
        tile.state = when {
            state is ConnState.Connected -> Tile.STATE_ACTIVE
            state.isActive -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                when {
                    state is ConnState.Connected -> R.string.tile_connected
                    state.isActive -> R.string.tile_searching
                    else -> R.string.tile_disconnected
                },
            )
        }
        tile.updateTile()
    }
}
