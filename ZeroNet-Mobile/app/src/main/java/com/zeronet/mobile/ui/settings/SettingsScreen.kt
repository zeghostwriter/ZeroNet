package com.zeronet.mobile.ui.settings

import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.AppFilterMode
import com.zeronet.mobile.model.AppLanguage
import com.zeronet.mobile.model.AutoConnect
import com.zeronet.mobile.model.ConnectionMode
import com.zeronet.mobile.model.EvasionLevel
import com.zeronet.mobile.model.MotionLevel
import com.zeronet.mobile.model.Palette
import com.zeronet.mobile.model.RemoteDns
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.model.ThemeMode
import com.zeronet.mobile.ui.components.Hairline
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.IconBadge
import com.zeronet.mobile.ui.components.LabeledBlock
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.QrCode
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.shell.LargeTitle
import com.zeronet.mobile.ui.shell.LocalBottomBarSpace
import com.zeronet.mobile.ui.shell.ScreenTopBar
import com.zeronet.mobile.ui.theme.ZeroPalettes
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Countries
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.theme.ZeroMotion
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.rememberHazeState

enum class SettingsCardId { Connection, Sources, Split, Share, Evasion, Appearance, Privacy, About }

enum class SettingsSheet { ConnectionMore, Sources, Countries, Apps, Licences, ClearHistory }

@Immutable
data class SettingsUiState(
    val settings: Settings = Settings(),
    val connected: Boolean = false,
    /** Cards whose changed options only apply after reconnecting. */
    val reconnectCards: Set<SettingsCardId> = emptySet(),
    val subscriptions: List<Subscription> = emptyList(),
    /** Countries seen in the server list, for the preferred-countries picker. */
    val knownCountries: List<String> = emptyList(),
    val discoveredCount: Int = 0,
    val lanAddresses: List<String> = emptyList(),
    val lanPermissionDenied: Boolean = false,
    val versionName: String = "",
    val versionCode: Int = 0,
    val dynamicColorAvailable: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S,
)

@Immutable
data class SettingsActions(
    val onChange: ((Settings) -> Settings) -> Unit = {},
    val onReconnect: () -> Unit = {},
    /** Turning LAN sharing on may need a runtime permission first. */
    val onLanShare: (Boolean) -> Unit = {},
    val onOpenVpnSettings: () -> Unit = {},
    val onAddSubscription: (name: String, url: String) -> Unit = { _, _ -> },
    val onRemoveSubscription: (Subscription) -> Unit = {},
    val onClearHistory: () -> Unit = {},
    val onCopy: (String) -> Unit = {},
)

@Composable
fun SettingsScreen(
    state: SettingsUiState,
    actions: SettingsActions,
    modifier: Modifier = Modifier,
    initialQuery: String = "",
    initialSheet: SettingsSheet? = null,
) {
    val context = LocalContext.current
    val haze = rememberHazeState()
    val listState = rememberLazyListState()
    val scrolled by remember { derivedStateOf { listState.firstVisibleItemIndex > 0 || listState.firstVisibleItemScrollOffset > 8 } }
    var queryText by rememberSaveable { mutableStateOf(initialQuery) }
    var sheet by rememberSaveable { mutableStateOf(initialSheet) }
    val index = remember(context) { SettingsSearchIndex(context) }
    val q = remember(queryText, index) { SettingsQuery(queryText, index) }
    val s = state.settings
    val status = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()

    Box(modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().hazeSource(haze),
            contentPadding = PaddingValues(top = status + 56.dp, bottom = LocalBottomBarSpace.current + 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "title", contentType = "title") { LargeTitle(stringResource(R.string.tab_settings)) }
            item(key = "search", contentType = "search") {
                ZeroTextField(
                    value = queryText,
                    onValueChange = { queryText = it },
                    placeholder = stringResource(R.string.settings_search),
                    leading = ZeroIcons.Search,
                    clearLabel = stringResource(R.string.action_clear),
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            val cards = SettingsCardId.entries.filter { cardVisible(it, q, state) }
            if (cards.isEmpty()) {
                item(key = "none", contentType = "none") {
                    Text(
                        stringResource(R.string.settings_no_results, queryText.trim()),
                        style = MaterialTheme.typography.bodyMedium,
                        color = ZeroTheme.colors.muted,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(32.dp),
                    )
                }
            }
            cards.forEach { id ->
                item(key = id.name, contentType = "card") {
                    val reconnect = id in state.reconnectCards
                    Box(Modifier.padding(horizontal = 16.dp).animateItem(fadeInSpec = ZeroMotion.quick(), placementSpec = ZeroMotion.quickOffset(), fadeOutSpec = ZeroMotion.quick())) {
                        when (id) {
                            SettingsCardId.Connection -> ConnectionCard(s, q, reconnect, actions) { sheet = SettingsSheet.ConnectionMore }
                            SettingsCardId.Sources -> SourcesCard(state, q, actions, onManage = { sheet = SettingsSheet.Sources }, onCountries = { sheet = SettingsSheet.Countries })
                            SettingsCardId.Split -> SplitCard(s, q, reconnect, actions) { sheet = SettingsSheet.Apps }
                            SettingsCardId.Share -> ShareCard(state, q, actions)
                            SettingsCardId.Evasion -> EvasionCard(s, q, reconnect, actions)
                            SettingsCardId.Appearance -> AppearanceCard(state, q, actions)
                            SettingsCardId.Privacy -> PrivacyCard(state, q, actions) { sheet = SettingsSheet.ClearHistory }
                            SettingsCardId.About -> AboutCard(state) { sheet = SettingsSheet.Licences }
                        }
                    }
                }
            }
        }
        ScreenTopBar(stringResource(R.string.tab_settings), scrolled, haze)
    }

    ConnectionMoreSheet(sheet == SettingsSheet.ConnectionMore, s, SettingsCardId.Connection in state.reconnectCards, actions) { sheet = null }
    SourcesSheet(sheet == SettingsSheet.Sources, s, state.subscriptions, actions) { sheet = null }
    CountriesSheet(sheet == SettingsSheet.Countries, s, state.knownCountries, actions) { sheet = null }
    AppPickerSheet(sheet == SettingsSheet.Apps, s, actions) { sheet = null }
    LicencesSheet(sheet == SettingsSheet.Licences) { sheet = null }
    ClearHistorySheet(sheet == SettingsSheet.ClearHistory, state.discoveredCount, actions) { sheet = null }
}

// ------------------------------------------------------------------ search keys

private val CONNECTION_KEYS = intArrayOf(
    R.string.settings_connection, R.string.settings_mode, R.string.settings_mode_vpn, R.string.settings_mode_proxy,
    R.string.settings_autoconnect, R.string.settings_autoswitch, R.string.settings_more_connection,
    R.string.settings_kill_switch, R.string.settings_ipv6, R.string.settings_mtu, R.string.kw_connection,
)
private val SOURCES_KEYS = intArrayOf(
    R.string.settings_sources_card, R.string.settings_sources, R.string.settings_preferred_countries,
    R.string.settings_refresh, R.string.settings_subscriptions, R.string.kw_sources,
)
private val SPLIT_KEYS = intArrayOf(
    R.string.settings_split, R.string.settings_iran_direct, R.string.settings_apps, R.string.settings_bypass_lan, R.string.kw_split,
)
private val SHARE_KEYS = intArrayOf(R.string.settings_share, R.string.settings_share_toggle, R.string.settings_share_auth, R.string.kw_share)
private val EVASION_KEYS = intArrayOf(
    R.string.settings_evasion, R.string.settings_evasion_level, R.string.settings_block_quic,
    R.string.settings_remote_dns, R.string.settings_block_ads, R.string.kw_evasion,
)
private val APPEARANCE_KEYS = intArrayOf(
    R.string.settings_appearance, R.string.settings_palette, R.string.settings_theme_mode, R.string.settings_amoled,
    R.string.settings_dynamic, R.string.settings_language, R.string.settings_motion, R.string.kw_appearance,
)
private val PRIVACY_KEYS = intArrayOf(R.string.settings_privacy, R.string.settings_logs, R.string.settings_clear_history, R.string.kw_privacy)
private val ABOUT_KEYS = intArrayOf(R.string.settings_about, R.string.settings_version, R.string.settings_licences, R.string.settings_engine, R.string.kw_about)

private fun cardVisible(id: SettingsCardId, q: SettingsQuery, state: SettingsUiState): Boolean = when (id) {
    SettingsCardId.Connection -> q.hit(*CONNECTION_KEYS)
    SettingsCardId.Sources -> q.hit(*SOURCES_KEYS)
    SettingsCardId.Split -> q.hit(*SPLIT_KEYS)
    SettingsCardId.Share -> q.hit(*SHARE_KEYS)
    SettingsCardId.Evasion -> q.hit(*EVASION_KEYS)
    SettingsCardId.Appearance -> q.hit(*APPEARANCE_KEYS)
    SettingsCardId.Privacy -> q.hit(*PRIVACY_KEYS)
    SettingsCardId.About -> q.hit(*ABOUT_KEYS)
}

/** Whether a row shows: everything when the card's own title (or its keywords) match, otherwise only matching rows. */
private class CardFilter(private val q: SettingsQuery, titleRes: Int, keywordRes: Int) {
    private val all = q.isEmpty || q.hit(titleRes, keywordRes)
    fun show(vararg ids: Int): Boolean = all || q.hit(*ids)
}

// ------------------------------------------------------------------ card chrome

@Composable
private fun SettingsCard(
    icon: ImageVector,
    title: String,
    reconnect: Boolean = false,
    onReconnect: () -> Unit = {},
    tint: Color = ZeroTheme.colors.accent,
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = ZeroTheme.colors
    ZeroCard(Modifier.fillMaxWidth().animateContentSize(ZeroMotion.quickSize()), padding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconBadge(icon, size = 36.dp, tint = tint)
            Spacer(Modifier.width(12.dp))
            Text(title, style = MaterialTheme.typography.titleMedium, color = c.text, modifier = Modifier.weight(1f).semantics { heading() })
        }
        AnimatedVisibility(reconnect, enter = fadeIn(ZeroMotion.quick()) + expandVertically(ZeroMotion.quickSize()), exit = fadeOut(ZeroMotion.quick()) + shrinkVertically(ZeroMotion.quickSize())) {
            ReconnectChip(onReconnect, Modifier.padding(top = 12.dp))
        }
        Spacer(Modifier.height(4.dp))
        content()
    }
}

@Composable
fun ReconnectChip(onReconnect: () -> Unit, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    Row(
        modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(RowShape)
            .background(c.warn.copy(alpha = 0.12f))
            .clickable(role = Role.Button, onClick = onReconnect)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(ZeroIcons.Refresh, null, tint = c.warn, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(10.dp))
        Text(stringResource(R.string.settings_applies_next), style = MaterialTheme.typography.bodySmall, color = c.text, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.settings_reconnect_now), style = MaterialTheme.typography.labelLarge, color = c.warn)
    }
}

@Composable
private fun Note(text: String, color: Color = ZeroTheme.colors.muted, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = color, modifier = modifier.padding(vertical = 4.dp))
}

// ------------------------------------------------------------------ cards

@Composable
private fun ConnectionCard(s: Settings, q: SettingsQuery, reconnect: Boolean, actions: SettingsActions, onMore: () -> Unit) {
    val f = CardFilter(q, R.string.settings_connection, R.string.kw_connection)
    SettingsCard(ZeroIcons.Bolt, stringResource(R.string.settings_connection), reconnect, actions.onReconnect) {
        if (f.show(R.string.settings_mode, R.string.settings_mode_vpn, R.string.settings_mode_proxy)) {
            LabeledBlock(
                stringResource(R.string.settings_mode),
                subtitle = stringResource(if (s.mode == ConnectionMode.Vpn) R.string.settings_mode_vpn_hint else R.string.settings_mode_proxy_hint),
            ) {
                Segmented(
                    ConnectionMode.entries, s.mode, { m -> actions.onChange { it.copy(mode = m) } },
                    label = { stringResource(if (it == ConnectionMode.Vpn) R.string.settings_mode_vpn else R.string.settings_mode_proxy) },
                )
            }
        }
        if (f.show(R.string.settings_autoconnect)) {
            LabeledBlock(stringResource(R.string.settings_autoconnect)) {
                Segmented(
                    AutoConnect.entries, s.autoConnect, { v -> actions.onChange { it.copy(autoConnect = v) } },
                    label = {
                        stringResource(
                            when (it) {
                                AutoConnect.Off -> R.string.option_off
                                AutoConnect.OnAppStart -> R.string.settings_autoconnect_app
                                AutoConnect.OnBoot -> R.string.settings_autoconnect_boot
                            },
                        )
                    },
                )
            }
        }
        if (f.show(R.string.settings_autoswitch)) {
            ToggleRow(
                stringResource(R.string.settings_autoswitch),
                s.autoSwitch,
                { v -> actions.onChange { it.copy(autoSwitch = v) } },
                subtitle = stringResource(R.string.settings_autoswitch_hint),
            )
        }
        if (f.show(R.string.settings_more_connection, R.string.settings_kill_switch, R.string.settings_ipv6, R.string.settings_mtu)) {
            NavRow(
                stringResource(R.string.settings_more_connection),
                onMore,
                subtitle = stringResource(R.string.settings_more_connection_hint),
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SourcesCard(state: SettingsUiState, q: SettingsQuery, actions: SettingsActions, onManage: () -> Unit, onCountries: () -> Unit) {
    val s = state.settings
    val locale = currentLocale()
    val f = CardFilter(q, R.string.settings_sources_card, R.string.kw_sources)
    SettingsCard(ZeroIcons.Globe, stringResource(R.string.settings_sources_card)) {
        if (f.show(R.string.settings_sources, R.string.settings_subscriptions)) {
            val enabled = Sources.builtIn.count { it.id !in s.disabledSources }
            val value = stringResource(R.string.settings_sources_value, Num.int(enabled, locale), Num.int(Sources.builtIn.size, locale)) +
                if (state.subscriptions.isNotEmpty()) " · " + androidx.compose.ui.res.pluralStringResource(R.plurals.subscriptions_count, state.subscriptions.size, Num.int(state.subscriptions.size, locale)) else ""
            NavRow(stringResource(R.string.settings_sources), onManage, subtitle = value)
        }
        if (f.show(R.string.settings_preferred_countries)) {
            LabeledBlock(stringResource(R.string.settings_preferred_countries), subtitle = stringResource(R.string.settings_preferred_countries_hint)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    s.preferredCountries.forEach { code ->
                        val name = Countries.name(code, locale).ifBlank { code }
                        val flag = Countries.flag(code).takeIf { Countries.canDraw(it) }
                        ZeroChip(
                            text = listOfNotNull(flag, name).joinToString(" "),
                            onClick = { actions.onChange { it.copy(preferredCountries = it.preferredCountries - code) } },
                            trailing = ZeroIcons.Close,
                            modifier = Modifier.semantics { contentDescription = name },
                        )
                    }
                    ZeroChip(stringResource(R.string.action_add), onCountries, icon = ZeroIcons.Plus, tint = ZeroTheme.colors.accent)
                }
            }
        }
        if (f.show(R.string.settings_refresh)) {
            LabeledBlock(stringResource(R.string.settings_refresh), subtitle = stringResource(if (s.autoRefresh) R.string.settings_refresh_auto_hint else R.string.settings_refresh_manual_hint)) {
                Segmented(
                    listOf(true, false), s.autoRefresh, { v -> actions.onChange { it.copy(autoRefresh = v) } },
                    label = { stringResource(if (it) R.string.settings_refresh_auto else R.string.settings_refresh_manual) },
                )
            }
        }
    }
}

@Composable
private fun SplitCard(s: Settings, q: SettingsQuery, reconnect: Boolean, actions: SettingsActions, onApps: () -> Unit) {
    val locale = currentLocale()
    val f = CardFilter(q, R.string.settings_split, R.string.kw_split)
    SettingsCard(ZeroIcons.Split, stringResource(R.string.settings_split), reconnect, actions.onReconnect) {
        if (f.show(R.string.settings_iran_direct)) {
            ToggleRow(
                stringResource(R.string.settings_iran_direct),
                s.iranDirect,
                { v -> actions.onChange { it.copy(iranDirect = v) } },
                subtitle = stringResource(R.string.settings_iran_direct_hint),
            )
        }
        if (f.show(R.string.settings_apps)) {
            LabeledBlock(stringResource(R.string.settings_apps), subtitle = if (s.mode == ConnectionMode.Proxy) stringResource(R.string.settings_apps_proxy_note) else null) {
                Segmented(
                    AppFilterMode.entries, s.appFilter, { v -> actions.onChange { it.copy(appFilter = v) } },
                    label = {
                        stringResource(
                            when (it) {
                                AppFilterMode.All -> R.string.settings_apps_all
                                AppFilterMode.OnlySelected -> R.string.settings_apps_only
                                AppFilterMode.AllExceptSelected -> R.string.settings_apps_except
                            },
                        )
                    },
                )
            }
            AnimatedVisibility(s.appFilter != AppFilterMode.All, enter = fadeIn(ZeroMotion.quick()) + expandVertically(ZeroMotion.quickSize()), exit = fadeOut(ZeroMotion.quick()) + shrinkVertically(ZeroMotion.quickSize())) {
                NavRow(
                    stringResource(R.string.settings_choose_apps),
                    onApps,
                    icon = ZeroIcons.Apps,
                    value = if (s.filteredApps.isEmpty()) stringResource(R.string.settings_apps_none) else androidx.compose.ui.res.pluralStringResource(R.plurals.apps_selected, s.filteredApps.size, Num.int(s.filteredApps.size, locale)),
                )
            }
        }
        if (f.show(R.string.settings_bypass_lan)) {
            ToggleRow(
                stringResource(R.string.settings_bypass_lan),
                s.bypassLan,
                { v -> actions.onChange { it.copy(bypassLan = v) } },
                subtitle = stringResource(R.string.settings_bypass_lan_hint),
            )
        }
    }
}

@Composable
private fun ShareCard(state: SettingsUiState, q: SettingsQuery, actions: SettingsActions) {
    val s = state.settings
    val c = ZeroTheme.colors
    val f = CardFilter(q, R.string.settings_share, R.string.kw_share)
    SettingsCard(ZeroIcons.Wifi, stringResource(R.string.settings_share), tint = c.info) {
        ToggleRow(
            stringResource(R.string.settings_share_toggle),
            s.lanShare,
            actions.onLanShare,
            subtitle = stringResource(R.string.settings_share_hint),
        )
        if (state.lanPermissionDenied && !s.lanShare) {
            Note(stringResource(R.string.settings_share_permission_denied), c.warn)
        }
        AnimatedVisibility(s.lanShare, enter = fadeIn(ZeroMotion.quick()) + expandVertically(ZeroMotion.quickSize()), exit = fadeOut(ZeroMotion.quick()) + shrinkVertically(ZeroMotion.quickSize())) {
            Column {
                Note(
                    stringResource(if (state.connected) R.string.settings_share_live else R.string.settings_share_when_connected),
                    if (state.connected) c.ok else c.warn,
                )
                if (state.lanAddresses.isEmpty()) {
                    Note(stringResource(R.string.settings_share_no_network))
                } else {
                    state.lanAddresses.forEach { ip -> LanEndpointCard(ip, s, actions.onCopy) }
                }
                if (f.show(R.string.settings_share_auth)) {
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.settings_share_auth), style = MaterialTheme.typography.bodyLarge, color = c.text)
                    Note(stringResource(R.string.settings_share_auth_hint))
                    Spacer(Modifier.height(6.dp))
                    var user by rememberSaveable(s.lanUser) { mutableStateOf(s.lanUser) }
                    var pass by rememberSaveable(s.lanPass) { mutableStateOf(s.lanPass) }
                    val commit = { actions.onChange { it.copy(lanUser = user.trim(), lanPass = pass) } }
                    ZeroTextField(
                        value = user,
                        onValueChange = { user = it },
                        placeholder = stringResource(R.string.settings_share_user),
                        imeAction = androidx.compose.ui.text.input.ImeAction.Next,
                        onImeAction = commit,
                    )
                    Spacer(Modifier.height(8.dp))
                    ZeroTextField(
                        value = pass,
                        onValueChange = { pass = it },
                        placeholder = stringResource(R.string.settings_share_pass),
                        keyboardType = KeyboardType.Password,
                        visualTransformation = PasswordVisualTransformation(),
                        onImeAction = commit,
                    )
                    val dirty = user.trim() != s.lanUser || pass != s.lanPass
                    AnimatedVisibility(dirty) {
                        Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.End) {
                            ZeroChip(stringResource(R.string.action_save), onClick = commit, icon = ZeroIcons.Check, selected = true)
                        }
                    }
                    if (s.lanUser.isNotBlank()) {
                        Note(stringResource(R.string.settings_share_http_off), c.warn)
                    }
                }
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

@Composable
private fun LanEndpointCard(ip: String, s: Settings, onCopy: (String) -> Unit) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val withAuth = s.lanUser.isNotBlank()
    val socksUri = socksUri(ip, s)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .clip(RoundedCornerShape(20.dp))
            .background(c.surfaceHi)
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_share_address), style = MaterialTheme.typography.labelMedium, color = c.muted)
                Text(com.zeronet.mobile.ui.util.ltr(ip), style = MaterialTheme.typography.titleLarge, color = c.text, maxLines = 1)
            }
        }
        Spacer(Modifier.height(8.dp))
        EndpointLine(stringResource(R.string.settings_share_socks), Num.int(s.socksPort, locale), "$ip:${s.socksPort}", onCopy)
        if (!withAuth) {
            EndpointLine(stringResource(R.string.settings_share_http), Num.int(s.httpPort, locale), "$ip:${s.httpPort}", onCopy)
        }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            QrCode(socksUri, stringResource(R.string.settings_share_qr_description, ip), Modifier.size(132.dp))
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_share_qr_hint), style = MaterialTheme.typography.bodySmall, color = c.muted)
                Spacer(Modifier.height(8.dp))
                ZeroChip(stringResource(R.string.action_copy_link), onClick = { onCopy(socksUri) }, icon = ZeroIcons.Copy)
            }
        }
    }
}

@Composable
private fun EndpointLine(label: String, port: String, copyValue: String, onCopy: (String) -> Unit) {
    val c = ZeroTheme.colors
    Row(Modifier.fillMaxWidth().heightIn(min = 44.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = c.muted, modifier = Modifier.weight(1f))
        Text(stringResource(R.string.settings_share_port, port), style = MaterialTheme.typography.bodyLarge, color = c.text)
        IconAction(ZeroIcons.Copy, stringResource(R.string.action_copy_value, label), onClick = { onCopy(copyValue) }, tint = c.muted, iconSize = 18.dp, size = 44.dp)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvasionCard(s: Settings, q: SettingsQuery, reconnect: Boolean, actions: SettingsActions) {
    val f = CardFilter(q, R.string.settings_evasion, R.string.kw_evasion)
    SettingsCard(ZeroIcons.Shield, stringResource(R.string.settings_evasion), reconnect, actions.onReconnect) {
        if (f.show(R.string.settings_evasion_level)) {
            LabeledBlock(
                stringResource(R.string.settings_evasion_level),
                subtitle = stringResource(
                    when (s.evasion) {
                        EvasionLevel.Off -> R.string.settings_evasion_off_hint
                        EvasionLevel.Auto -> R.string.settings_evasion_auto_hint
                        EvasionLevel.Strong -> R.string.settings_evasion_strong_hint
                    },
                ),
            ) {
                Segmented(
                    EvasionLevel.entries, s.evasion, { v -> actions.onChange { it.copy(evasion = v) } },
                    label = {
                        stringResource(
                            when (it) {
                                EvasionLevel.Off -> R.string.option_off
                                EvasionLevel.Auto -> R.string.option_auto
                                EvasionLevel.Strong -> R.string.settings_evasion_strong
                            },
                        )
                    },
                )
            }
        }
        if (f.show(R.string.settings_block_quic)) {
            ToggleRow(stringResource(R.string.settings_block_quic), s.blockQuic, { v -> actions.onChange { it.copy(blockQuic = v) } }, subtitle = stringResource(R.string.settings_block_quic_hint))
        }
        if (f.show(R.string.settings_remote_dns)) {
            LabeledBlock(stringResource(R.string.settings_remote_dns), subtitle = stringResource(R.string.settings_remote_dns_hint)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RemoteDns.entries.forEach { dns ->
                        val enabled = s.customDns.isBlank()
                        ZeroChip(
                            text = when (dns) {
                                RemoteDns.Cloudflare -> "Cloudflare"
                                RemoteDns.Google -> "Google"
                                RemoteDns.Quad9 -> "Quad9"
                                RemoteDns.AdGuard -> "AdGuard"
                            },
                            selected = enabled && s.remoteDns == dns,
                            onClick = { actions.onChange { it.copy(remoteDns = dns) } },
                            modifier = Modifier.semantics { this.selected = enabled && s.remoteDns == dns },
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                var custom by rememberSaveable(s.customDns) { mutableStateOf(s.customDns) }
                val commitCustom = { actions.onChange { it.copy(customDns = custom.trim()) } }
                ZeroTextField(
                    value = custom,
                    onValueChange = { custom = it },
                    placeholder = stringResource(R.string.settings_custom_dns_hint),
                    keyboardType = KeyboardType.Uri,
                    onImeAction = commitCustom,
                    clearLabel = stringResource(R.string.action_clear),
                )
                Note(stringResource(R.string.settings_custom_dns_note))
                val dirty = custom.trim() != s.customDns
                AnimatedVisibility(dirty) {
                    Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.End) {
                        ZeroChip(stringResource(R.string.action_save), onClick = commitCustom, icon = ZeroIcons.Check, selected = true)
                    }
                }
            }
        }
        if (f.show(R.string.settings_block_ads)) {
            ToggleRow(stringResource(R.string.settings_block_ads), s.blockAds, { v -> actions.onChange { it.copy(blockAds = v) } }, subtitle = stringResource(R.string.settings_block_ads_hint))
        }
    }
}

@Composable
private fun AppearanceCard(state: SettingsUiState, q: SettingsQuery, actions: SettingsActions) {
    val s = state.settings
    val f = CardFilter(q, R.string.settings_appearance, R.string.kw_appearance)
    SettingsCard(ZeroIcons.Palette, stringResource(R.string.settings_appearance)) {
        if (f.show(R.string.settings_palette)) {
            LabeledBlock(stringResource(R.string.settings_palette), subtitle = if (s.dynamicColor && state.dynamicColorAvailable) stringResource(R.string.settings_palette_dynamic_note) else null) {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Palette.entries.forEach { p ->
                        PaletteSwatch(p, selected = s.palette == p) { actions.onChange { it.copy(palette = p) } }
                    }
                }
            }
        }
        if (f.show(R.string.settings_theme_mode)) {
            LabeledBlock(stringResource(R.string.settings_theme_mode)) {
                Segmented(
                    ThemeMode.entries, s.themeMode, { v -> actions.onChange { it.copy(themeMode = v) } },
                    label = {
                        stringResource(
                            when (it) {
                                ThemeMode.System -> R.string.option_system
                                ThemeMode.Light -> R.string.settings_theme_light
                                ThemeMode.Dark -> R.string.settings_theme_dark
                            },
                        )
                    },
                )
            }
        }
        if (f.show(R.string.settings_amoled)) {
            ToggleRow(
                stringResource(R.string.settings_amoled),
                s.amoled,
                { v -> actions.onChange { it.copy(amoled = v) } },
                subtitle = stringResource(R.string.settings_amoled_hint),
                enabled = s.themeMode != ThemeMode.Light,
            )
        }
        if (state.dynamicColorAvailable && f.show(R.string.settings_dynamic)) {
            ToggleRow(
                stringResource(R.string.settings_dynamic),
                s.dynamicColor,
                { v -> actions.onChange { it.copy(dynamicColor = v) } },
                subtitle = stringResource(R.string.settings_dynamic_hint),
            )
        }
        if (f.show(R.string.settings_language)) {
            LabeledBlock(stringResource(R.string.settings_language)) {
                Segmented(
                    AppLanguage.entries, s.language, { v -> actions.onChange { it.copy(language = v) } },
                    label = {
                        when (it) {
                            AppLanguage.System -> stringResource(R.string.option_system)
                            AppLanguage.English -> "English"
                            AppLanguage.Persian -> "فارسی"
                        }
                    },
                )
            }
        }
        if (f.show(R.string.settings_motion)) {
            LabeledBlock(stringResource(R.string.settings_motion), subtitle = stringResource(if (s.motion == MotionLevel.Full) R.string.settings_motion_full_hint else R.string.settings_motion_reduced_hint)) {
                Segmented(
                    MotionLevel.entries, s.motion, { v -> actions.onChange { it.copy(motion = v) } },
                    label = { stringResource(if (it == MotionLevel.Full) R.string.settings_motion_full else R.string.settings_motion_reduced) },
                )
            }
        }
    }
}

@Composable
private fun PaletteSwatch(p: Palette, selected: Boolean, onClick: () -> Unit) {
    val c = ZeroTheme.colors
    val (bg, accent) = remember(p) { ZeroPalettes.swatch(p) }
    val name = stringResource(paletteName(p))
    Column(
        Modifier
            .width(76.dp)
            .clip(RowShape)
            .selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
            .padding(vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier
                .size(52.dp)
                .clip(CircleShape)
                .border(if (selected) 2.5.dp else 1.dp, if (selected) c.accent else c.border, CircleShape)
                .padding(if (selected) 5.dp else 3.dp)
                .clip(CircleShape)
                .background(bg)
                .drawBehind {
                    val r = size.minDimension / 2
                    drawCircle(accent, r * 0.62f, style = androidx.compose.ui.graphics.drawscope.Stroke(r * 0.12f))
                    drawCircle(accent, r * 0.22f, Offset(size.width / 2, size.height / 2))
                },
            contentAlignment = Alignment.Center,
        ) {}
        Spacer(Modifier.height(6.dp))
        Text(
            name,
            style = MaterialTheme.typography.labelMedium,
            color = if (selected) c.text else c.muted,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
        )
    }
}

fun paletteName(p: Palette): Int = when (p) {
    Palette.GoldenDark -> R.string.palette_golden
    Palette.Nightshade -> R.string.palette_nightshade
    Palette.Arctic -> R.string.palette_arctic
    Palette.Sakura -> R.string.palette_sakura
    Palette.Paper -> R.string.palette_paper
    Palette.Contrast -> R.string.palette_contrast
}

@Composable
private fun PrivacyCard(state: SettingsUiState, q: SettingsQuery, actions: SettingsActions, onClear: () -> Unit) {
    val s = state.settings
    val c = ZeroTheme.colors
    val f = CardFilter(q, R.string.settings_privacy, R.string.kw_privacy)
    SettingsCard(ZeroIcons.Lock, stringResource(R.string.settings_privacy)) {
        if (f.show(R.string.settings_logs)) {
            ToggleRow(stringResource(R.string.settings_logs), s.logs, { v -> actions.onChange { it.copy(logs = v) } }, subtitle = stringResource(R.string.settings_logs_hint))
        }
        if (f.show(R.string.settings_clear_history)) {
            NavRow(
                stringResource(R.string.settings_clear_history),
                onClear,
                subtitle = stringResource(R.string.settings_clear_history_hint),
                tint = c.err,
                icon = ZeroIcons.Trash,
            )
        }
    }
}

@Composable
private fun AboutCard(state: SettingsUiState, onLicences: () -> Unit) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    SettingsCard(ZeroIcons.Info, stringResource(R.string.settings_about), tint = c.muted) {
        Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.settings_version), style = MaterialTheme.typography.bodyLarge, color = c.text, modifier = Modifier.weight(1f))
            Text(
                com.zeronet.mobile.ui.util.ltr(Num.localize(state.versionName, locale)) + " (" + Num.int(state.versionCode, locale) + ")",
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
            )
        }
        Hairline()
        Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_engine), style = MaterialTheme.typography.bodyLarge, color = c.text)
                Text(stringResource(R.string.settings_engine_hint), style = MaterialTheme.typography.bodySmall, color = c.muted)
            }
            Text("Zray-Core", style = MaterialTheme.typography.bodyMedium, color = c.muted)
        }
        Hairline()
        NavRow(stringResource(R.string.settings_licences), onLicences, subtitle = stringResource(R.string.settings_licences_hint))
        Spacer(Modifier.height(4.dp))
    }
}

/** "socks5://[user:pass@]ip:port", with the credentials percent-encoded so any character survives. */
fun socksUri(ip: String, s: Settings): String {
    val auth = if (s.lanUser.isNotBlank()) {
        java.net.URLEncoder.encode(s.lanUser, "UTF-8").replace("+", "%20") + ":" +
            java.net.URLEncoder.encode(s.lanPass, "UTF-8").replace("+", "%20") + "@"
    } else {
        ""
    }
    return "socks5://$auth$ip:${s.socksPort}"
}
