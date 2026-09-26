package com.zeronet.mobile.ui.settings

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.zeronet.mobile.R
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.ui.components.FlagBadge
import com.zeronet.mobile.ui.components.Hairline
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.IconBadge
import com.zeronet.mobile.ui.components.LabeledBlock
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.SectionTitle
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Countries
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatAgo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

// ------------------------------------------------------------------ shared chrome

/** Title and optional one-line explanation at the top of a settings sheet. */
@Composable
internal fun SheetHeader(title: String, body: String? = null) {
    val c = ZeroTheme.colors
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 8.dp)) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = c.text, modifier = Modifier.semantics { heading() })
        if (body != null) {
            Spacer(Modifier.height(4.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = c.muted)
        }
    }
}

/** A scrolling sheet body with the standard side padding. */
@Composable
internal fun ColumnScope.SheetBody(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .weight(1f, fill = false)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
            .padding(bottom = 16.dp),
        content = content,
    )
}

// ------------------------------------------------------------------ connection

private val MTU_OPTIONS = listOf(1280, 1400, 1500, 9000)

/** Kill switch (Android's always-on + lockdown), IPv6 and MTU. */
@Composable
fun ConnectionMoreSheet(visible: Boolean, s: Settings, reconnect: Boolean, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_more_connection)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val locale = currentLocale()
        SheetHeader(title)
        SheetBody {
            if (reconnect) {
                ReconnectChip(actions.onReconnect, Modifier.padding(bottom = 8.dp))
            }
            // Kill switch: ZeroNet's own, which holds a blocking interface
            // whenever no server carries traffic, and Android's lock-down,
            // which also covers the moments ZeroNet itself is not running.
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .background(c.surfaceHi)
                    .padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 16.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconBadge(ZeroIcons.Lock, size = 36.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.settings_kill_switch), style = MaterialTheme.typography.titleSmall, color = c.text)
                }
                ToggleRow(
                    stringResource(R.string.settings_kill_switch_app),
                    s.killSwitch,
                    { v -> actions.onChange { it.copy(killSwitch = v) } },
                    subtitle = stringResource(R.string.settings_kill_switch_app_hint),
                )
                Text(stringResource(R.string.settings_kill_switch_body), style = MaterialTheme.typography.bodySmall, color = c.muted)
                Spacer(Modifier.height(12.dp))
                TonalButton(
                    stringResource(R.string.settings_kill_switch_open),
                    actions.onOpenVpnSettings,
                    icon = ZeroIcons.External,
                    container = c.surface,
                )
            }
            TrustedNetworks(s, actions)
            ToggleRow(
                stringResource(R.string.settings_ipv6),
                s.ipv6,
                { v -> actions.onChange { it.copy(ipv6 = v) } },
                subtitle = stringResource(R.string.settings_ipv6_hint),
            )
            LabeledBlock(stringResource(R.string.settings_mtu), subtitle = stringResource(R.string.settings_mtu_hint, Num.int(1500, locale))) {
                val selected = MTU_OPTIONS.minByOrNull { kotlin.math.abs(it - s.mtu) } ?: 1500
                Segmented(
                    MTU_OPTIONS,
                    selected,
                    { v -> actions.onChange { it.copy(mtu = v) } },
                    label = { Num.int(it, locale) },
                )
            }
        }
    }
}

/**
 * Networks where ZeroNet stays off (home Wi-Fi, a free network abroad):
 * trust the current one, or remove one trusted earlier. Identified by
 * [com.zeronet.mobile.data.NetworkIdentity]'s hash, which needs no location
 * permission; the label is only what the user saw when trusting it.
 */
@Composable
private fun TrustedNetworks(s: Settings, actions: SettingsActions) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val current by produceState<Pair<String, String>?>(null) {
        value = withContext(Dispatchers.IO) {
            com.zeronet.mobile.data.NetworkIdentity.current(context)?.let { id ->
                id to com.zeronet.mobile.data.NetworkIdentity.label(context).ifBlank { context.getString(R.string.trusted_unknown_network) }
            }
        }
    }
    SectionTitle(stringResource(R.string.trusted_title), Modifier.padding(top = 12.dp))
    Text(stringResource(R.string.trusted_body), style = MaterialTheme.typography.bodySmall, color = c.muted, modifier = Modifier.padding(bottom = 8.dp))
    val here = current
    if (here != null && !s.trusts(here.first)) {
        TonalButton(
            stringResource(R.string.trusted_add, here.second),
            { actions.onChange { it.copy(trustedNetworks = (it.trustedNetworks + "${here.first}|${here.second}").distinctBy { e -> e.substringBefore('|') }) } },
            icon = ZeroIcons.Plus,
        )
        Spacer(Modifier.height(8.dp))
    }
    if (s.trustedNetworks.isEmpty()) {
        Text(stringResource(R.string.trusted_none), style = MaterialTheme.typography.bodyMedium, color = c.muted, modifier = Modifier.padding(vertical = 8.dp))
    }
    s.trustedNetworks.forEachIndexed { i, entry ->
        if (i > 0) Hairline()
        val id = entry.substringBefore('|')
        val label = entry.substringAfter('|')
        Row(Modifier.fillMaxWidth().heightIn(min = 52.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(ZeroIcons.Wifi, null, tint = c.muted, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.bodyLarge, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (here?.first == id) Text(stringResource(R.string.trusted_current), style = MaterialTheme.typography.bodySmall, color = c.ok)
            }
            IconAction(
                ZeroIcons.Trash,
                stringResource(R.string.trusted_remove, label),
                onClick = { actions.onChange { it.copy(trustedNetworks = it.trustedNetworks.filterNot { e -> e.substringBefore('|') == id }) } },
                tint = c.err,
            )
        }
    }
}

// ------------------------------------------------------------------ sources

/** Built-in public feeds (on/off) and the user's own subscriptions. */
@Composable
fun SourcesSheet(visible: Boolean, s: Settings, subscriptions: List<Subscription>, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_sources)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val context = LocalContext.current
        val locale = currentLocale()
        val now = remember(visible) { System.currentTimeMillis() }
        SheetHeader(title, stringResource(R.string.sources_body))
        SheetBody {
            SectionTitle(stringResource(R.string.sources_public), Modifier.padding(top = 4.dp))
            Sources.builtIn.forEachIndexed { i, src ->
                if (i > 0) Hairline()
                ToggleRow(
                    src.name,
                    src.id !in s.disabledSources,
                    { on -> actions.onChange { it.copy(disabledSources = if (on) it.disabledSources - src.id else it.disabledSources + src.id) } },
                    subtitle = stringResource(
                        when (src.tier) {
                            0 -> R.string.sources_tier_0
                            1 -> R.string.sources_tier_1
                            2 -> R.string.sources_tier_2
                            else -> R.string.sources_tier_3
                        },
                    ),
                )
            }
            Spacer(Modifier.height(12.dp))
            SectionTitle(stringResource(R.string.settings_subscriptions))
            if (subscriptions.isEmpty()) {
                Text(
                    stringResource(R.string.sources_no_subscriptions),
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.muted,
                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                )
            }
            subscriptions.forEach { sub ->
                val name = sub.name.ifBlank { sub.url.substringAfter("://").substringBefore('/') }
                Row(Modifier.fillMaxWidth().heightIn(min = 56.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconBadge(ZeroIcons.Link, size = 36.dp, tint = c.info)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, style = MaterialTheme.typography.bodyLarge, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            androidx.compose.ui.res.pluralStringResource(R.plurals.servers_count, sub.count, Num.int(sub.count, locale)) +
                                " · " + formatAgo(context, sub.updatedAt, now, locale),
                            style = MaterialTheme.typography.bodySmall,
                            color = c.muted,
                            maxLines = 1,
                        )
                    }
                    IconAction(
                        ZeroIcons.Trash,
                        stringResource(R.string.action_remove_subscription, name),
                        onClick = { actions.onRemoveSubscription(sub) },
                        tint = c.muted,
                        iconSize = 20.dp,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            AddSubscriptionForm(actions.onAddSubscription)
        }
    }
}

@Composable
private fun AddSubscriptionForm(onAdd: (String, String) -> Unit) {
    val c = ZeroTheme.colors
    var url by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }
    Text(stringResource(R.string.sources_add_title), style = MaterialTheme.typography.bodyLarge, color = c.text)
    Spacer(Modifier.height(8.dp))
    ZeroTextField(
        value = url,
        onValueChange = { url = it.trim(); invalid = false },
        placeholder = stringResource(R.string.import_sub_url),
        leading = ZeroIcons.Link,
        keyboardType = KeyboardType.Uri,
        imeAction = ImeAction.Next,
    )
    Spacer(Modifier.height(8.dp))
    ZeroTextField(value = name, onValueChange = { name = it }, placeholder = stringResource(R.string.import_sub_name))
    if (invalid) {
        Text(stringResource(R.string.import_sub_invalid), style = MaterialTheme.typography.bodySmall, color = c.err, modifier = Modifier.padding(top = 8.dp))
    }
    Spacer(Modifier.height(12.dp))
    PrimaryButton(
        stringResource(R.string.action_add),
        {
            val u = url.trim()
            if (!isSubscriptionUrl(u)) {
                invalid = true
            } else {
                onAdd(name.trim().ifBlank { u.substringAfter("://").substringBefore('/') }, u)
                url = ""
                name = ""
            }
        },
        Modifier.fillMaxWidth(),
        icon = ZeroIcons.Plus,
        enabled = url.isNotBlank(),
    )
}

/** An http(s) URL with a host. */
fun isSubscriptionUrl(url: String): Boolean {
    val u = url.trim()
    if (!(u.startsWith("https://", ignoreCase = true) || u.startsWith("http://", ignoreCase = true))) return false
    val host = u.substringAfter("://").substringBefore('/').substringBefore('?').substringAfterLast('@')
    return host.isNotBlank() && !host.any { it.isWhitespace() }
}

// ------------------------------------------------------------------ countries

/** Pick the countries "Fastest" should prefer. */
@Composable
fun CountriesSheet(visible: Boolean, s: Settings, knownCountries: List<String>, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_preferred_countries)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val locale = currentLocale()
        var query by rememberSaveable { mutableStateOf("") }
        val all = remember(knownCountries, s.preferredCountries, locale) {
            (s.preferredCountries + knownCountries + Countries.COMMON)
                .map { it.uppercase(Locale.ROOT) }
                .filter { it.length == 2 && Countries.name(it, locale).isNotBlank() }
                .distinct()
                .sortedBy { Countries.name(it, locale) }
        }
        val shown = remember(all, query, locale) {
            val q = SettingsSearchIndex.normalize(query)
            if (q.isEmpty()) all else all.filter {
                SettingsSearchIndex.normalize(Countries.name(it, locale)).contains(q) ||
                    Countries.name(it, Locale.ENGLISH).lowercase(Locale.ROOT).contains(q) ||
                    it.lowercase(Locale.ROOT) == q
            }
        }
        SheetHeader(title, stringResource(R.string.settings_preferred_countries_hint))
        ZeroTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = stringResource(R.string.countries_search),
            leading = ZeroIcons.Search,
            clearLabel = stringResource(R.string.action_clear),
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        Spacer(Modifier.height(8.dp))
        LazyColumn(Modifier.weight(1f, fill = false), contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)) {
            items(shown, key = { it }, contentType = { "country" }) { code ->
                val checked = code in s.preferredCountries
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .clip(RowShape)
                        .toggleable(checked, role = Role.Checkbox) { on ->
                            actions.onChange { st ->
                                st.copy(preferredCountries = if (on) st.preferredCountries + code else st.preferredCountries - code)
                            }
                        }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    FlagBadge(code, size = 36.dp)
                    Spacer(Modifier.width(14.dp))
                    Text(Countries.name(code, locale), style = MaterialTheme.typography.bodyLarge, color = c.text, modifier = Modifier.weight(1f))
                    CheckMark(checked)
                }
            }
        }
    }
}

@Composable
private fun CheckMark(checked: Boolean) {
    val c = ZeroTheme.colors
    Box(
        Modifier
            .size(24.dp)
            .clip(CircleShape)
            .background(if (checked) c.accent else c.surfaceHi),
        contentAlignment = Alignment.Center,
    ) {
        if (checked) Icon(ZeroIcons.Check, null, tint = c.onAccent, modifier = Modifier.size(16.dp))
    }
}

// ------------------------------------------------------------------ apps

@Immutable
private data class AppEntry(val pkg: String, val label: String)

/** Launchable apps (the manifest's <queries> allows exactly these), sorted by name. */
private fun loadApps(pm: PackageManager, self: String): List<AppEntry> {
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val infos = if (Build.VERSION.SDK_INT >= 33) {
        pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        pm.queryIntentActivities(intent, 0)
    }
    return infos
        .map { AppEntry(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
        .filter { it.pkg != self }
        .distinctBy { it.pkg }
        .sortedBy { it.label.lowercase() }
}

/** Choose which apps go through (or around) the VPN. */
@Composable
fun AppPickerSheet(visible: Boolean, s: Settings, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_choose_apps)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val context = LocalContext.current
        val apps by produceState<List<AppEntry>?>(null, visible) {
            if (visible && value == null) value = withContext(Dispatchers.IO) { runCatching { loadApps(context.packageManager, context.packageName) }.getOrDefault(emptyList()) }
        }
        var query by rememberSaveable { mutableStateOf("") }
        SheetHeader(
            title,
            stringResource(
                if (s.appFilter == com.zeronet.mobile.model.AppFilterMode.OnlySelected) R.string.apps_body_only else R.string.apps_body_except,
            ),
        )
        ZeroTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = stringResource(R.string.apps_search),
            leading = ZeroIcons.Search,
            clearLabel = stringResource(R.string.action_clear),
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        Spacer(Modifier.height(8.dp))
        val list = apps
        if (list == null) {
            Box(Modifier.fillMaxWidth().height(160.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = c.accent, strokeWidth = 2.dp, modifier = Modifier.size(28.dp))
            }
            return@ZeroSheet
        }
        val shown = remember(list, query, s.filteredApps) {
            val q = query.trim().lowercase()
            // Selected apps first, so the current choice is visible without scrolling.
            list.filter { q.isEmpty() || it.label.lowercase().contains(q) || it.pkg.contains(q) }
                .sortedBy { if (it.pkg in s.filteredApps) 0 else 1 }
        }
        LazyColumn(Modifier.weight(1f, fill = false), contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)) {
            items(shown, key = { it.pkg }, contentType = { "app" }) { app ->
                val checked = app.pkg in s.filteredApps
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 60.dp)
                        .clip(RowShape)
                        .toggleable(checked, role = Role.Checkbox) { on ->
                            actions.onChange { st -> st.copy(filteredApps = if (on) st.filteredApps + app.pkg else st.filteredApps - app.pkg) }
                        }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    AppIcon(app.pkg)
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(app.label, style = MaterialTheme.typography.bodyLarge, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(app.pkg, style = MaterialTheme.typography.bodySmall, color = c.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    CheckMark(checked)
                }
            }
        }
    }
}

@Composable
private fun AppIcon(pkg: String) {
    val context = LocalContext.current
    val c = ZeroTheme.colors
    val density = androidx.compose.ui.platform.LocalDensity.current
    val px = with(density) { 36.dp.roundToPx() }
    val icon by produceState<ImageBitmap?>(null, pkg) {
        value = withContext(Dispatchers.IO) {
            runCatching { context.packageManager.getApplicationIcon(pkg).toBitmap(px, px).asImageBitmap() }.getOrNull()
        }
    }
    val b = icon
    if (b != null) {
        Image(b, contentDescription = null, modifier = Modifier.size(36.dp))
    } else {
        Box(Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)).background(c.surfaceHi))
    }
}

// ------------------------------------------------------------------ licences

private data class Licence(val name: String, val licence: String, val asset: String)

private val LICENCES = listOf(
    Licence("ZeroNet · Zray-Core", "MIT", "MIT.txt"),
    Licence("shaped-rustls (rustls fork)", "MPL-2.0", "MPL-2.0.txt"),
    Licence("Vazirmatn", "SIL OFL 1.1", "Vazirmatn-OFL.txt"),
    Licence("AndroidX · Jetpack Compose", "Apache-2.0", "Apache-2.0.txt"),
    Licence("Kotlin · kotlinx.coroutines", "Apache-2.0", "Apache-2.0.txt"),
    Licence("Haze", "Apache-2.0", "Apache-2.0.txt"),
    Licence("ZXing", "Apache-2.0", "Apache-2.0.txt"),
)

@Composable
fun LicencesSheet(visible: Boolean, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_licences)
    var open by rememberSaveable { mutableStateOf<String?>(null) }
    ZeroSheet(visible = visible, onDismiss = { open = null; onDismiss() }, title = title) {
        val c = ZeroTheme.colors
        val context = LocalContext.current
        val asset = open
        if (asset == null) {
            SheetHeader(title, stringResource(R.string.licences_body))
            SheetBody {
                LICENCES.forEachIndexed { i, l ->
                    if (i > 0) Hairline()
                    NavRow(l.name, { open = l.asset }, value = l.licence)
                }
            }
        } else {
            val text by produceState<String?>(null, asset) {
                value = withContext(Dispatchers.IO) {
                    runCatching { context.assets.open("licenses/$asset").bufferedReader().use { it.readText() } }.getOrDefault("")
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                IconAction(ZeroIcons.Back, stringResource(R.string.action_back), onClick = { open = null })
                Text(asset.removeSuffix(".txt"), style = MaterialTheme.typography.titleMedium, color = c.text, modifier = Modifier.weight(1f).semantics { heading() })
            }
            SheetBody {
                val t = text
                if (t == null) {
                    CircularProgressIndicator(color = c.accent, strokeWidth = 2.dp, modifier = Modifier.size(28.dp))
                } else {
                    SelectionContainer {
                        // Licence texts are English and laid out for monospace.
                        androidx.compose.runtime.CompositionLocalProvider(
                            androidx.compose.ui.platform.LocalLayoutDirection provides androidx.compose.ui.unit.LayoutDirection.Ltr,
                        ) {
                            Text(t, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 16.sp), color = c.muted)
                        }
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ clear history

@Composable
fun ClearHistorySheet(visible: Boolean, discoveredCount: Int, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.settings_clear_history)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val locale = currentLocale()
        val context = LocalContext.current
        SheetHeader(
            title,
            if (discoveredCount > 0) {
                androidx.compose.ui.res.pluralStringResource(R.plurals.clear_history_body, discoveredCount, Num.grouped(discoveredCount.toLong(), locale))
            } else {
                stringResource(R.string.clear_history_nothing)
            },
        )
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TonalButton(stringResource(R.string.action_cancel), onDismiss, Modifier.weight(1f).heightIn(min = 52.dp))
            PrimaryButton(
                stringResource(R.string.action_clear),
                { actions.onClearHistory(); onDismiss() },
                Modifier.weight(1f),
                icon = ZeroIcons.Trash,
                enabled = discoveredCount > 0,
                container = c.err,
                content = if (c.isDark) c.bg else c.surface,
            )
        }
    }
}
