package com.zeronet.mobile.service

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import com.zeronet.mobile.BuildConfig
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.ui.MainActivity

/**
 * Home-screen widget: the connection state, the server in use with its ping,
 * and one button that connects or disconnects. Lives in the :vpn process
 * next to [Engine], which re-renders it on every state change, so it never
 * polls and costs nothing while the state is still.
 */
class ZeroWidget : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        val views = render(context, Engine.state.value)
        ids.forEach { manager.updateAppWidget(it, views) }
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TOGGLE) {
            toggle(context)
            return
        }
        super.onReceive(context, intent)
    }

    private fun toggle(context: Context) {
        if (Engine.state.value.isActive) {
            Engine.disconnect()
            return
        }
        val settings = Engine.snapshotSettings()
        // Rendering already sends the tap to the app when permission is
        // missing; checked again in case it was revoked since.
        if (settings.mode == ConnectionMode.Vpn && VpnService.prepare(context) != null) return
        Engine.prepare(ConnectTarget.decode(settings.lastTarget), settings)
        runCatching { ZeroVpnService.connect(context) }
    }

    companion object {
        private const val ACTION_TOGGLE = "${BuildConfig.APPLICATION_ID}.WIDGET_TOGGLE"

        /** What the widget last showed, so search progress (many states a second) does not redraw it. */
        @Volatile private var shown: Any? = null

        /** Re-render every placed widget; a no-op when there are none or nothing visible changed. */
        fun update(context: Context, state: ConnState) {
            val look: Any = when (state) {
                is ConnState.Connected -> listOf("on", state.server.name, state.delayMs)
                is ConnState.Searching, is ConnState.Connecting -> "search"
                is ConnState.Reconnecting -> listOf("re", state.reason)
                else -> state.javaClass.simpleName
            }
            if (look == shown) return
            runCatching {
                val manager = AppWidgetManager.getInstance(context) ?: return
                val ids = manager.getAppWidgetIds(ComponentName(context, ZeroWidget::class.java))
                if (ids.isEmpty()) return
                val views = render(context, state)
                ids.forEach { manager.updateAppWidget(it, views) }
                shown = look
            }
        }

        private fun render(context: Context, state: ConnState): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_zeronet)
            val title: String
            val subtitle: String
            val button: Int
            when (state) {
                is ConnState.Connected -> {
                    title = context.getString(R.string.tile_connected)
                    subtitle = if (state.delayMs >= 0) {
                        context.getString(R.string.notification_server_ping, state.server.name, state.delayMs)
                    } else {
                        state.server.name
                    }
                    button = R.drawable.widget_button_on
                }
                is ConnState.Reconnecting -> {
                    title = context.getString(
                        if (state.reason == Engine.REASON_BLOCKED) R.string.widget_blocked else R.string.notification_reconnecting,
                    )
                    subtitle = context.getString(R.string.widget_tap_disconnect)
                    button = R.drawable.widget_button_busy
                }
                is ConnState.Searching, is ConnState.Connecting -> {
                    title = context.getString(R.string.tile_searching)
                    subtitle = context.getString(R.string.widget_tap_disconnect)
                    button = R.drawable.widget_button_busy
                }
                is ConnState.Failed -> {
                    title = context.getString(R.string.widget_failed)
                    subtitle = context.getString(R.string.widget_tap_connect)
                    button = R.drawable.widget_button_off
                }
                else -> {
                    title = context.getString(R.string.tile_disconnected)
                    subtitle = context.getString(R.string.widget_tap_connect)
                    button = R.drawable.widget_button_off
                }
            }
            views.setTextViewText(R.id.widget_title, title)
            views.setTextViewText(R.id.widget_subtitle, subtitle)
            views.setInt(R.id.widget_button, "setBackgroundResource", button)
            views.setOnClickPendingIntent(R.id.widget_root, openApp(context))
            // Connecting needs the VPN permission, which only the app can ask
            // for: without it the button opens the app instead.
            val needsApp = !state.isActive && Engine.snapshotSettings().mode == ConnectionMode.Vpn &&
                runCatching { VpnService.prepare(context) != null }.getOrDefault(false)
            views.setOnClickPendingIntent(R.id.widget_button, if (needsApp) openApp(context) else toggleIntent(context))
            return views
        }

        private fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(
            context, 10,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        private fun toggleIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
            context, 11,
            Intent(context, ZeroWidget::class.java).setAction(ACTION_TOGGLE),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}
