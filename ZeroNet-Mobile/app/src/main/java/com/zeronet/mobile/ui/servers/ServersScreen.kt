package com.zeronet.mobile.ui.servers

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.ui.components.Badge
import com.zeronet.mobile.ui.components.CardShape
import com.zeronet.mobile.ui.components.FlagBadge
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.IconBadge
import com.zeronet.mobile.ui.components.PingBars
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.ProgressRing
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.model.CountryGroup
import com.zeronet.mobile.ui.model.countryLabel
import com.zeronet.mobile.ui.model.groupByCountry
import com.zeronet.mobile.ui.model.kindLabel
import com.zeronet.mobile.ui.model.serverTitle
import com.zeronet.mobile.ui.shell.LargeTitle
import com.zeronet.mobile.ui.shell.LocalBottomBarSpace
import com.zeronet.mobile.ui.shell.ScreenTopBar
import com.zeronet.mobile.ui.theme.Motion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Countries
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatAgo
import com.zeronet.mobile.ui.util.formatDelay
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.rememberHazeState
import java.util.Locale

enum class ServersSegment { Recommended, Countries, Mine }

@Immutable
data class ServersState(
    val servers: List<Server> = emptyList(),
    val subscriptions: List<Subscription> = emptyList(),
    val segment: ServersSegment = ServersSegment.Recommended,
    val query: String = "",
    val expanded: Set<String> = emptySet(),
    val refreshing: Boolean = false,
    /** (done, total) while a test-all runs. */
    val testProgress: Pair<Int, Int>? = null,
    /** Key of the server the tunnel currently runs through. */
    val activeKey: String? = null,
    val now: Long = System.currentTimeMillis(),
)

@Immutable
data class ServersActions(
    val onSegment: (ServersSegment) -> Unit = {},
    val onQuery: (String) -> Unit = {},
    val onToggleCountry: (String) -> Unit = {},
    val onRefresh: () -> Unit = {},
    val onTest: () -> Unit = {},
    val onConnect: (ConnectTarget) -> Unit = {},
    val onFavorite: (Server, Boolean) -> Unit = { _, _ -> },
    val onDetails: (Server) -> Unit = {},
    val onAdd: () -> Unit = {},
    val onRemoveSubscription: (Subscription) -> Unit = {},
)

private fun matches(s: Server, q: String, locale: Locale): Boolean {
    if (q.isBlank()) return true
    val needle = q.trim().lowercase(locale)
    return s.name.lowercase(locale).contains(needle) ||
        s.host.lowercase(Locale.ROOT).contains(needle) ||
        s.country.lowercase(Locale.ROOT) == needle ||
        Countries.name(s.country, locale).lowercase(locale).contains(needle) ||
        Countries.name(s.country, Locale.ENGLISH).lowercase(Locale.ENGLISH).contains(needle)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServersScreen(state: ServersState, actions: ServersActions, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val haze = rememberHazeState()
    val listState = rememberLazyListState()
    val scrolled by remember { derivedStateOf { listState.firstVisibleItemIndex > 0 || listState.firstVisibleItemScrollOffset > 8 } }

    // Filtering and grouping recompute only when their inputs change.
    val allServers by rememberUpdatedState(state.servers)
    val query by rememberUpdatedState(state.query)
    val filtered by remember(locale) { derivedStateOf { allServers.filter { matches(it, query, locale) } } }
    val recommended by remember { derivedStateOf { filtered.filter { it.delayMs >= 0 }.sortedBy { it.delayMs } } }
    val groups by remember { derivedStateOf { groupByCountry(filtered) } }
    val mine by remember { derivedStateOf { filtered.filter { it.isUser } } }
    val working by remember { derivedStateOf { allServers.count { it.delayMs >= 0 } } }

    Box(modifier.fillMaxSize()) {
        val pull = rememberPullToRefreshState()
        val status = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
        PullToRefreshBox(
            isRefreshing = state.refreshing,
            onRefresh = actions.onRefresh,
            state = pull,
            modifier = Modifier.fillMaxSize(),
            indicator = {
                PullToRefreshDefaults.Indicator(
                    state = pull,
                    isRefreshing = state.refreshing,
                    containerColor = c.surfaceHi,
                    color = c.accent,
                    modifier = Modifier.align(Alignment.TopCenter).padding(top = status + 56.dp),
                )
            },
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().hazeSource(haze),
                contentPadding = PaddingValues(top = status + 56.dp, bottom = LocalBottomBarSpace.current + 24.dp),
            ) {
                item(key = "title", contentType = "title") {
                    val subtitle = if (state.servers.isEmpty()) {
                        stringResource(R.string.servers_subtitle_empty)
                    } else {
                        pluralStringResource(
                            R.plurals.servers_subtitle,
                            state.servers.size,
                            Num.grouped(state.servers.size.toLong(), locale),
                            Num.int(working, locale),
                        )
                    }
                    LargeTitle(stringResource(R.string.tab_servers), subtitle = subtitle)
                }
                if (state.servers.isEmpty()) {
                    item(key = "empty", contentType = "empty") {
                        EmptyServers(state.refreshing, actions.onRefresh, actions.onAdd)
                    }
                    return@LazyColumn
                }
                item(key = "controls", contentType = "controls") {
                    Column(Modifier.padding(horizontal = 16.dp)) {
                        ZeroTextField(
                            value = state.query,
                            onValueChange = actions.onQuery,
                            placeholder = stringResource(R.string.servers_search),
                            leading = ZeroIcons.Search,
                            clearLabel = stringResource(R.string.action_clear),
                        )
                        Spacer(Modifier.height(12.dp))
                        Segmented(
                            options = ServersSegment.entries,
                            selected = state.segment,
                            onSelect = actions.onSegment,
                            label = { stringResource(it.labelRes()) },
                        )
                        TestProgress(state.testProgress)
                        Spacer(Modifier.height(8.dp))
                    }
                }
                when (state.segment) {
                    ServersSegment.Recommended -> {
                        if (recommended.isEmpty()) {
                            item(key = "rec_empty", contentType = "empty") {
                                if (state.query.isNotBlank()) {
                                    NoMatches(state.query)
                                } else {
                                    InlineEmpty(
                                        title = stringResource(R.string.servers_rec_empty_title),
                                        body = stringResource(R.string.servers_rec_empty_body),
                                        action = stringResource(R.string.action_test_servers),
                                        busy = state.testProgress != null,
                                        onAction = actions.onTest,
                                    )
                                }
                            }
                        } else {
                            items(recommended, key = { "r_" + it.key }, contentType = { "server" }) { s ->
                                ServerRow(s, s.key == state.activeKey, actions, Modifier.animateItem())
                            }
                        }
                    }
                    ServersSegment.Countries -> {
                        if (groups.isEmpty()) {
                            item(key = "cty_empty", contentType = "empty") { NoMatches(state.query) }
                        }
                        groups.forEach { g ->
                            val code = g.code
                            val open = code in state.expanded || (state.query.isNotBlank() && groups.size == 1)
                            item(key = "c_$code", contentType = "country") {
                                CountryRow(g, open, actions, Modifier.animateItem())
                            }
                            if (open) {
                                items(g.servers, key = { "c_${code}_" + it.key }, contentType = { "server" }) { s ->
                                    ServerRow(s, s.key == state.activeKey, actions, Modifier.animateItem(), indent = true)
                                }
                            }
                        }
                    }
                    ServersSegment.Mine -> {
                        item(key = "add", contentType = "add") { AddRow(actions.onAdd, Modifier.animateItem()) }
                        if (state.subscriptions.isNotEmpty()) {
                            item(key = "subs_title", contentType = "section") { Section(stringResource(R.string.servers_subscriptions)) }
                            items(state.subscriptions, key = { "sub_" + it.id }, contentType = { "sub" }) { sub ->
                                SubscriptionRow(sub, state.now, actions.onRemoveSubscription, Modifier.animateItem())
                            }
                        }
                        if (mine.isNotEmpty()) {
                            item(key = "mine_title", contentType = "section") { Section(stringResource(R.string.servers_your_servers)) }
                            items(mine, key = { "m_" + it.key }, contentType = { "server" }) { s ->
                                ServerRow(s, s.key == state.activeKey, actions, Modifier.animateItem())
                            }
                        } else if (state.subscriptions.isEmpty()) {
                            item(key = "mine_empty", contentType = "empty") {
                                if (state.query.isNotBlank()) {
                                    NoMatches(state.query)
                                } else {
                                    InlineEmpty(
                                        title = stringResource(R.string.servers_mine_empty_title),
                                        body = stringResource(R.string.servers_mine_empty_body),
                                        action = null,
                                        busy = false,
                                        onAction = {},
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        ScreenTopBar(stringResource(R.string.tab_servers), scrolled, haze) {
            IconAction(
                ZeroIcons.Refresh,
                stringResource(R.string.action_refresh_servers),
                onClick = actions.onRefresh,
                enabled = !state.refreshing,
            )
            TestAction(state.testProgress, actions.onTest, enabled = state.servers.isNotEmpty())
        }
    }
}

private fun ServersSegment.labelRes() = when (this) {
    ServersSegment.Recommended -> R.string.servers_recommended
    ServersSegment.Countries -> R.string.servers_countries
    ServersSegment.Mine -> R.string.servers_mine
}

@Composable
private fun TestAction(progress: Pair<Int, Int>?, onTest: () -> Unit, enabled: Boolean) {
    val c = ZeroTheme.colors
    Box(contentAlignment = Alignment.Center) {
        if (progress != null) {
            val fraction = if (progress.second > 0) progress.first.toFloat() / progress.second else 0f
            val animated by animateFloatAsState(fraction, Motion.standard(), label = "testProgress")
            ProgressRing({ animated }, Modifier.size(36.dp), color = c.accent, track = c.border, stroke = 2.5.dp)
        }
        IconAction(
            ZeroIcons.Bolt,
            stringResource(R.string.action_test_servers),
            onClick = onTest,
            enabled = enabled && progress == null,
            tint = if (progress != null) c.accent else c.text,
        )
    }
}

@Composable
private fun TestProgress(progress: Pair<Int, Int>?) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    AnimatedVisibility(progress != null, enter = fadeIn(), exit = fadeOut()) {
        val p = progress ?: (0 to 0)
        Text(
            stringResource(R.string.servers_testing, Num.int(p.first, locale), Num.int(p.second, locale)),
            style = MaterialTheme.typography.bodySmall,
            color = c.accent,
            modifier = Modifier.padding(top = 10.dp, start = 4.dp),
        )
    }
}

@Composable
private fun Section(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = ZeroTheme.colors.muted,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 16.dp, bottom = 4.dp),
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ServerRow(server: Server, active: Boolean, actions: ServersActions, modifier: Modifier = Modifier, indent: Boolean = false) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val haptics = LocalHapticFeedback.current
    val title = serverTitle(context, server, locale)
    val country = countryLabel(context, server.country, locale)
    val kind = kindLabel(context, server.kind)
    val delay = formatDelay(context, server.delayMs, locale)
    val favLabel = stringResource(if (server.favorite) R.string.action_unfavorite else R.string.action_favorite)
    val detailsLabel = stringResource(R.string.action_details)
    val connectLabel = stringResource(R.string.action_connect)
    val activeLabel = stringResource(R.string.state_active)
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .heightIn(min = 68.dp)
            .clip(RowShape)
            .background(if (active) c.ok.copy(alpha = 0.10f) else androidx.compose.ui.graphics.Color.Transparent)
            .combinedClickable(
                onClickLabel = connectLabel,
                onLongClickLabel = detailsLabel,
                role = Role.Button,
                onLongClick = {
                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                    actions.onDetails(server)
                },
                onClick = { actions.onConnect(ConnectTarget.Specific(server.key)) },
            )
            .semantics {
                contentDescription = "$title, $country, $kind, $delay"
                if (active) stateDescription = activeLabel
                customActions = listOf(
                    CustomAccessibilityAction(favLabel) { actions.onFavorite(server, !server.favorite); true },
                    CustomAccessibilityAction(detailsLabel) { actions.onDetails(server); true },
                )
            }
            .padding(start = if (indent) 24.dp else 8.dp, end = 0.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FlagBadge(server.country, size = if (indent) 32.dp else 40.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge(kind, when (server.kind) {
                    com.zeronet.mobile.model.ServerKind.Direct -> c.accent
                    com.zeronet.mobile.model.ServerKind.Cdn -> c.info
                    com.zeronet.mobile.model.ServerKind.Other -> c.muted
                })
                if (!indent && country.isNotBlank() && country != title) {
                    Spacer(Modifier.width(6.dp))
                    Text(country, style = MaterialTheme.typography.bodySmall, color = c.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            PingBars(server.delayMs)
            Spacer(Modifier.height(4.dp))
            Text(delay, style = MaterialTheme.typography.labelMedium, color = c.delayColor(server.delayMs), maxLines = 1)
        }
        IconAction(
            if (server.favorite) ZeroIcons.StarFilled else ZeroIcons.Star,
            favLabel,
            onClick = { actions.onFavorite(server, !server.favorite) },
            tint = if (server.favorite) c.accent else c.muted,
            iconSize = 20.dp,
        )
        IconAction(ZeroIcons.ChevronEnd, detailsLabel, onClick = { actions.onDetails(server) }, tint = c.muted, iconSize = 18.dp, size = 40.dp)
    }
}

@Composable
private fun CountryRow(group: CountryGroup, expanded: Boolean, actions: ServersActions, modifier: Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val name = countryLabel(context, group.code, locale)
    val count = pluralStringResource(R.plurals.servers_count, group.count, Num.int(group.count, locale))
    val working = if (group.working > 0) stringResource(R.string.servers_working_count, Num.int(group.working, locale)) else null
    val rotation by animateFloatAsState(if (expanded) 180f else 0f, Motion.standard(), label = "chevron")
    val expandLabel = stringResource(if (expanded) R.string.action_collapse else R.string.action_expand)
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .heightIn(min = 68.dp)
            .clip(RowShape)
            .clickable(
                role = Role.Button,
                onClickLabel = stringResource(R.string.action_connect),
                enabled = group.code.isNotEmpty(),
                onClick = { actions.onConnect(ConnectTarget.Country(group.code)) },
            )
            .padding(start = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FlagBadge(group.code)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.titleSmall, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                listOfNotNull(count, working).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = c.muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (group.bestDelay >= 0) {
            Column(horizontalAlignment = Alignment.End) {
                PingBars(group.bestDelay)
                Spacer(Modifier.height(4.dp))
                Text(formatDelay(context, group.bestDelay, locale), style = MaterialTheme.typography.labelMedium, color = c.delayColor(group.bestDelay))
            }
        }
        Box(
            Modifier
                .size(48.dp)
                .clip(CircleShape)
                .clickable(role = Role.Button, onClickLabel = expandLabel) { actions.onToggleCountry(group.code) }
                .semantics { contentDescription = "$expandLabel $name" },
            contentAlignment = Alignment.Center,
        ) {
            Icon(ZeroIcons.ChevronDown, null, tint = c.muted, modifier = Modifier.size(20.dp).graphicsLayer { rotationZ = rotation })
        }
    }
}

@Composable
private fun AddRow(onAdd: () -> Unit, modifier: Modifier) {
    val c = ZeroTheme.colors
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .heightIn(min = 64.dp)
            .clip(CardShape)
            .background(c.surface)
            .clickable(role = Role.Button, onClick = onAdd)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconBadge(ZeroIcons.Plus)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(stringResource(R.string.servers_add_title), style = MaterialTheme.typography.titleSmall, color = c.text)
            Text(stringResource(R.string.servers_add_body), style = MaterialTheme.typography.bodySmall, color = c.muted)
        }
        Icon(ZeroIcons.ChevronEnd, null, tint = c.muted, modifier = Modifier.size(20.dp))
    }
}

@Composable
private fun SubscriptionRow(sub: Subscription, now: Long, onRemove: (Subscription) -> Unit, modifier: Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val name = sub.name.ifBlank { sub.url.substringAfter("://").substringBefore('/') }
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .heightIn(min = 64.dp)
            .padding(start = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconBadge(ZeroIcons.Link, tint = c.info)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.titleSmall, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                pluralStringResource(R.plurals.servers_count, sub.count, Num.int(sub.count, locale)) + " · " + formatAgo(context, sub.updatedAt, now, locale),
                style = MaterialTheme.typography.bodySmall,
                color = c.muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconAction(ZeroIcons.Trash, stringResource(R.string.action_remove_subscription, name), onClick = { onRemove(sub) }, tint = c.muted, iconSize = 20.dp)
    }
}

@Composable
private fun NoMatches(query: String) {
    val c = ZeroTheme.colors
    Text(
        stringResource(R.string.servers_no_matches, query.trim()),
        style = MaterialTheme.typography.bodyMedium,
        color = c.muted,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 40.dp),
    )
}

@Composable
private fun InlineEmpty(title: String, body: String, action: String?, busy: Boolean, onAction: () -> Unit) {
    val c = ZeroTheme.colors
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, color = c.text, textAlign = TextAlign.Center)
        Spacer(Modifier.height(6.dp))
        Text(body, style = MaterialTheme.typography.bodyMedium, color = c.muted, textAlign = TextAlign.Center)
        if (action != null) {
            Spacer(Modifier.height(16.dp))
            TonalButton(action, onAction, icon = ZeroIcons.Bolt, enabled = !busy)
        }
    }
}

/** First run: nothing discovered yet. An illustration, one sentence, one button. */
@Composable
private fun EmptyServers(refreshing: Boolean, onFind: () -> Unit, onAdd: () -> Unit) {
    val c = ZeroTheme.colors
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 32.dp)
            .padding(top = 24.dp, bottom = 16.dp)
            .animateContentSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        EmptyIllustration(Modifier.size(180.dp))
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(R.string.servers_empty_title),
            style = MaterialTheme.typography.titleLarge,
            color = c.text,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.servers_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = c.muted,
            textAlign = TextAlign.Center,
            modifier = Modifier.widthIn(max = 360.dp),
        )
        Spacer(Modifier.height(24.dp))
        PrimaryButton(
            text = stringResource(if (refreshing) R.string.servers_finding else R.string.action_find_servers),
            onClick = onFind,
            icon = ZeroIcons.Search,
            loading = refreshing,
        )
        Spacer(Modifier.height(8.dp))
        TonalButton(stringResource(R.string.servers_add_title), onAdd, icon = ZeroIcons.Plus, container = androidx.compose.ui.graphics.Color.Transparent)
    }
}

/** Concentric rings with scattered "server" dots: the orb, looking outward. */
@Composable
fun EmptyIllustration(modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    Box(
        modifier.drawWithCache {
            val center = Offset(size.width / 2, size.height / 2)
            val r = size.minDimension / 2
            val ring = androidx.compose.ui.graphics.drawscope.Stroke(1.5.dp.toPx())
            val dots = listOf(0.15f to 0.9f, 0.62f to 0.74f, 1.1f to 0.95f, 1.9f to 0.62f, 2.5f to 0.88f, 3.3f to 0.8f, 4.1f to 0.93f, 4.8f to 0.66f, 5.6f to 0.84f)
            val glow = androidx.compose.ui.graphics.Brush.radialGradient(
                listOf(c.accent.copy(alpha = 0.22f), androidx.compose.ui.graphics.Color.Transparent),
                center = center,
                radius = r * 0.7f,
            )
            onDrawBehind {
                drawCircle(glow, r * 0.7f, center)
                drawCircle(c.border, r * 0.96f, center, style = ring)
                drawCircle(c.border, r * 0.72f, center, style = ring)
                drawCircle(c.border, r * 0.48f, center, style = ring)
                dots.forEachIndexed { i, (a, d) ->
                    val p = Offset(center.x + kotlin.math.cos(a) * r * d, center.y + kotlin.math.sin(a) * r * d)
                    drawCircle(if (i % 3 == 0) c.accent else c.muted.copy(alpha = 0.7f), (if (i % 3 == 0) 4.5f else 3f) * density, p)
                }
                drawCircle(c.accent, r * 0.16f, center)
                drawCircle(c.surface, r * 0.07f, center)
            }
        },
    )
}
