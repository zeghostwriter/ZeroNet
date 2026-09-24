package com.zeronet.mobile.ui.home

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zeronet.mobile.R
import com.zeronet.mobile.data.NetworkIdentity
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.ui.LocalController
import com.zeronet.mobile.ui.components.FlagBadge
import com.zeronet.mobile.ui.components.IconBadge
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.SectionTitle
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.model.CountryGroup
import com.zeronet.mobile.ui.model.countryLabel
import com.zeronet.mobile.ui.model.groupByCountry
import com.zeronet.mobile.ui.model.serverTitle
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatDelay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun HomeRoute() {
    val controller = LocalController.current
    val conn by controller.engine.state.collectAsStateWithLifecycle()
    val stats by controller.engine.stats.collectAsStateWithLifecycle()
    val settings by controller.settings.settings.collectAsStateWithLifecycle()
    val servers by controller.servers.servers.collectAsStateWithLifecycle()
    val target = remember(settings.lastTarget) { ConnectTarget.decode(settings.lastTarget) }
    val groups by produceState(emptyList<CountryGroup>(), servers) {
        value = withContext(Dispatchers.Default) { groupByCountry(servers) }
    }
    val targetServer = remember(target, servers) { (target as? ConnectTarget.Specific)?.let { t -> servers.firstOrNull { it.key == t.key } } }
    val countryDelay = remember(target, groups) { (target as? ConnectTarget.Country)?.let { t -> groups.firstOrNull { it.code == t.code }?.bestDelay } ?: -1 }
    val network = rememberNetworkLabel()
    var picker by rememberSaveable { mutableStateOf(false) }

    HomeScreen(
        state = HomeState(
            conn = conn,
            stats = stats,
            target = target,
            targetServer = targetServer,
            targetCountryDelay = countryDelay,
            network = network,
        ),
        onOrbClick = controller::toggle,
        onRetry = {
            val failed = conn as? ConnState.Failed
            if (failed?.reason == FailReason.ServerUnavailable) controller.selectTarget(ConnectTarget.Fastest) else controller.connect()
        },
        onPickServer = { picker = true },
    )

    ServerPickerSheet(
        visible = picker,
        target = target,
        groups = groups,
        favorites = remember(servers) { servers.filter { it.favorite } },
        onSelect = {
            picker = false
            controller.selectTarget(it)
        },
        onDismiss = { picker = false },
    )
}

/** "Wi-Fi" / carrier name, following the default network live. */
@Composable
private fun rememberNetworkLabel(): String {
    val context = LocalContext.current
    var label by remember { mutableStateOf(NetworkIdentity.label(context)) }
    DisposableEffect(context) {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) { label = safeLabel(context) }
            override fun onLost(network: Network) { label = safeLabel(context) }
            override fun onAvailable(network: Network) { label = safeLabel(context) }
        }
        val registered = runCatching { cm?.registerDefaultNetworkCallback(callback) }.isSuccess && cm != null
        onDispose { if (registered) runCatching { cm.unregisterNetworkCallback(callback) } }
    }
    return label
}

private fun safeLabel(context: Context): String = runCatching { NetworkIdentity.label(context) }.getOrDefault("")

/** Fastest / favourites / countries. Choosing one saves it as the target and connects. */
@Composable
fun ServerPickerSheet(
    visible: Boolean,
    target: ConnectTarget,
    groups: List<CountryGroup>,
    favorites: List<Server>,
    onSelect: (ConnectTarget) -> Unit,
    onDismiss: () -> Unit,
) {
    val title = stringResource(R.string.picker_title)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val context = LocalContext.current
        val locale = currentLocale()
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            color = c.text,
            modifier = Modifier.padding(horizontal = 24.dp).padding(bottom = 8.dp),
        )
        LazyColumn(
            modifier = Modifier.weight(1f, fill = false),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
        ) {
            item(key = "fastest", contentType = "row") {
                PickerRow(
                    selected = target == ConnectTarget.Fastest,
                    leading = { IconBadge(ZeroIcons.Bolt) },
                    title = stringResource(R.string.server_fastest),
                    subtitle = stringResource(R.string.server_fastest_hint),
                    trailing = null,
                    onClick = { onSelect(ConnectTarget.Fastest) },
                )
            }
            if (favorites.isNotEmpty()) {
                item(key = "fav_title", contentType = "title") { SectionTitle(stringResource(R.string.picker_favorites), Modifier.padding(start = 8.dp, top = 8.dp)) }
                items(favorites, key = { "fav_" + it.key }, contentType = { "row" }) { s ->
                    PickerRow(
                        selected = target == ConnectTarget.Specific(s.key),
                        leading = { FlagBadge(s.country) },
                        title = serverTitle(context, s, locale),
                        subtitle = countryLabel(context, s.country, locale),
                        trailing = if (s.delayMs >= 0) formatDelay(context, s.delayMs, locale) else null,
                        trailingColor = c.delayColor(s.delayMs),
                        onClick = { onSelect(ConnectTarget.Specific(s.key)) },
                    )
                }
            }
            val known = groups.filter { it.code.isNotEmpty() }
            if (known.isNotEmpty()) {
                item(key = "cty_title", contentType = "title") { SectionTitle(stringResource(R.string.picker_countries), Modifier.padding(start = 8.dp, top = 8.dp)) }
                items(known, key = { "cty_" + it.code }, contentType = { "row" }) { g ->
                    PickerRow(
                        selected = target == ConnectTarget.Country(g.code),
                        leading = { FlagBadge(g.code) },
                        title = countryLabel(context, g.code, locale),
                        subtitle = androidx.compose.ui.res.pluralStringResource(R.plurals.servers_count, g.count, Num.int(g.count, locale)),
                        trailing = if (g.bestDelay >= 0) formatDelay(context, g.bestDelay, locale) else null,
                        trailingColor = c.delayColor(g.bestDelay),
                        onClick = { onSelect(ConnectTarget.Country(g.code)) },
                    )
                }
            } else {
                item(key = "empty", contentType = "empty") {
                    Text(
                        stringResource(R.string.picker_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.muted,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 16.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun PickerRow(
    selected: Boolean,
    leading: @Composable () -> Unit,
    title: String,
    subtitle: String,
    trailing: String?,
    onClick: () -> Unit,
    trailingColor: androidx.compose.ui.graphics.Color = ZeroTheme.colors.muted,
) {
    val c = ZeroTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .clip(RowShape)
            .background(if (selected) c.accent.copy(alpha = 0.10f) else androidx.compose.ui.graphics.Color.Transparent)
            .clickable(role = Role.Button, onClick = onClick)
            .semantics { this.selected = selected }
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        leading()
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            Text(trailing, style = MaterialTheme.typography.labelLarge, color = trailingColor)
        }
        if (selected) {
            Spacer(Modifier.width(8.dp))
            Icon(ZeroIcons.Check, null, tint = c.accent, modifier = Modifier.size(20.dp))
        }
    }
}
