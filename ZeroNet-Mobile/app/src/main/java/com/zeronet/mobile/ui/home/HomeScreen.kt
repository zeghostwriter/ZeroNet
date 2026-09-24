package com.zeronet.mobile.ui.home

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.DiscoveryStage
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.TrafficStats
import com.zeronet.mobile.ui.components.Badge
import com.zeronet.mobile.ui.components.FlagBadge
import com.zeronet.mobile.ui.components.IconBadge
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.model.countryLabel
import com.zeronet.mobile.ui.model.failReasonText
import com.zeronet.mobile.ui.model.kindLabel
import com.zeronet.mobile.ui.model.serverTitle
import com.zeronet.mobile.ui.shell.LocalBottomBarSpace
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.Motion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.theme.latinTracking
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatDelay
import com.zeronet.mobile.ui.util.formatDuration
import com.zeronet.mobile.ui.util.formatRate
import com.zeronet.mobile.ui.theme.ZeroMotion
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay

@Immutable
data class HomeState(
    val conn: ConnState = ConnState.Idle,
    val stats: TrafficStats = TrafficStats(),
    val target: ConnectTarget = ConnectTarget.Fastest,
    /** The server a [ConnectTarget.Specific] target points at, when known. */
    val targetServer: Server? = null,
    /** Best known delay in the target country, or -1. */
    val targetCountryDelay: Int = -1,
    /** Wall clock used for the session timer; tests pin it. */
    val now: Long = 0L,
    val profile: ConnectionProfile = ConnectionProfile.Normal,
)

@Composable
fun HomeScreen(
    state: HomeState,
    onOrbClick: () -> Unit,
    onRetry: () -> Unit,
    onPickServer: () -> Unit,
    modifier: Modifier = Modifier,
    onProfile: (ConnectionProfile) -> Unit = {},
) {
    val c = ZeroTheme.colors
    val conn = state.conn
    val phase = when (conn) {
        ConnState.Idle -> OrbPhase.Idle
        is ConnState.Connected -> OrbPhase.Connected
        is ConnState.Failed -> OrbPhase.Failed
        else -> OrbPhase.Busy
    }
    Box(modifier.fillMaxSize()) {
        StateBackdrop(phase, gaming = state.profile == ConnectionProfile.Gaming)
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val orbSize = minOf(maxWidth - 64.dp, maxHeight * 0.44f, 320.dp).coerceAtLeast(180.dp)
            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .windowInsetsPadding(WindowInsets.statusBars)
                    .padding(bottom = LocalBottomBarSpace.current + 8.dp)
                    .heightIn(min = maxHeight - LocalBottomBarSpace.current - 8.dp - WindowInsetsTop()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                HomeHeader()
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    val gaming = state.profile == ConnectionProfile.Gaming
                    ConnectGlobe(
                        phase = phase,
                        label = stringResource(orbLabel(conn)),
                        actionLabel = stringResource(if (conn.isActive) R.string.orb_action_disconnect else R.string.orb_action_connect),
                        stateText = orbStateText(state),
                        destination = routeDestination(state),
                        gaming = gaming,
                        gamingTitle = stringResource(R.string.gaming_title),
                        hudText = (conn as? ConnState.Connected)?.takeIf { gaming && it.delayMs >= 0 }?.let {
                            stringResource(R.string.gaming_ping, Num.int(it.delayMs, currentLocale()))
                        },
                        onClick = onOrbClick,
                        modifier = Modifier.size(orbSize),
                    )
                    StatusLine(state, onRetry, Modifier.padding(horizontal = 24.dp))
                }
                Column(
                    Modifier
                        .widthIn(max = 560.dp)
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                ) {
                    ProfileSelector(state.profile, onProfile)
                    Spacer(Modifier.height(12.dp))
                    ServerCard(state, onPickServer)
                    AnimatedVisibility(
                        visible = conn is ConnState.Connected,
                        enter = fadeIn(tween(ZeroMotion.ms(220))) + expandVertically(Motion.standard()),
                        exit = fadeOut(tween(ZeroMotion.ms(150))) + shrinkVertically(Motion.standard()),
                    ) {
                        if (conn is ConnState.Connected) {
                            Column {
                                Spacer(Modifier.height(12.dp))
                                StatsCard(state.stats, conn.since, state.now)
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }
            }
        }
    }
}

@Composable
private fun WindowInsetsTop() = androidx.compose.foundation.layout.WindowInsets.statusBars
    .let { with(androidx.compose.ui.platform.LocalDensity.current) { it.getTop(this).toDp() } }

/** The country the route on the globe ends in: the live server, else the chosen target. */
private fun routeDestination(state: HomeState): String? {
    val code = when (val conn = state.conn) {
        is ConnState.Connected -> conn.server.country
        is ConnState.Connecting -> conn.server?.country
        else -> null
    } ?: when (val t = state.target) {
        is ConnectTarget.Specific -> state.targetServer?.country
        is ConnectTarget.Country -> t.code
        else -> null
    }
    return code?.takeIf { it.length == 2 }
}

private fun orbLabel(conn: ConnState): Int = when (conn) {
    ConnState.Idle -> R.string.orb_connect
    is ConnState.Connected -> R.string.orb_connected
    is ConnState.Failed -> R.string.orb_failed
    ConnState.Disconnecting -> R.string.orb_disconnecting
    else -> R.string.orb_connecting
}

@Composable
private fun orbStateText(state: HomeState): String {
    val context = LocalContext.current
    val locale = currentLocale()
    return when (val conn = state.conn) {
        ConnState.Idle -> stringResource(R.string.state_disconnected)
        is ConnState.Connected -> stringResource(R.string.state_connected_to, countryLabel(context, conn.server.country, locale))
        is ConnState.Failed -> failReasonText(context, conn.reason)
        ConnState.Disconnecting -> stringResource(R.string.stage_disconnecting)
        else -> stringResource(R.string.state_connecting)
    }
}

@Composable
private fun HomeHeader() {
    val c = ZeroTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 20.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BrandMark(Modifier.size(22.dp))
        Spacer(Modifier.width(10.dp))
        Text(
            stringResource(R.string.brand_name),
            style = MaterialTheme.typography.titleMedium,
            color = c.text,
            modifier = Modifier.weight(1f).semantics { heading() },
        )
    }
}

/** The ZeroNet logo, as in the launcher icon. */
@Composable
fun BrandMark(modifier: Modifier = Modifier) {
    androidx.compose.foundation.Image(
        painter = androidx.compose.ui.res.painterResource(R.drawable.zeronet_logo),
        contentDescription = null,
        modifier = modifier.clip(androidx.compose.foundation.shape.RoundedCornerShape(22)),
    )
}

@Composable
private fun StatusLine(state: HomeState, onRetry: () -> Unit, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val conn = state.conn
    Column(
        modifier
            .heightIn(min = 72.dp)
            .padding(top = 8.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val text: String = when (conn) {
            // The orb and the line under it already say "not connected" / "connected to X".
            ConnState.Idle -> ""
            is ConnState.Searching -> {
                val p = conn.progress
                when (p.stage) {
                    DiscoveryStage.History -> stringResource(R.string.stage_history)
                    DiscoveryStage.Fetch -> stringResource(R.string.stage_fetch)
                    DiscoveryStage.Parse -> stringResource(R.string.stage_parse, Num.grouped(p.candidates.toLong(), locale))
                    DiscoveryStage.Tcp -> stringResource(
                        R.string.stage_tcp,
                        Num.grouped(p.tcpDone.toLong(), locale),
                        Num.int(p.tcpOpen, locale),
                    )
                    DiscoveryStage.Real -> stringResource(
                        R.string.stage_real,
                        Num.grouped((p.tcpDone.coerceAtLeast(p.realDone)).toLong(), locale),
                        Num.int(p.alive, locale),
                    )
                }
            }
            is ConnState.Connecting -> conn.server?.let {
                stringResource(R.string.stage_connecting_to, countryLabel(context, it.country, locale))
            } ?: stringResource(R.string.stage_connecting)
            is ConnState.Reconnecting -> stringResource(R.string.stage_reconnecting)
            ConnState.Disconnecting -> stringResource(R.string.stage_disconnecting)
            is ConnState.Connected -> if (conn.pool > 1) {
                stringResource(R.string.stage_connected_pool, Num.int(conn.pool - 1, locale))
            } else {
                ""
            }
            is ConnState.Failed -> failReasonText(context, conn.reason)
        }
        val reduced = LocalReducedMotion.current
        AnimatedContent(
            targetState = text,
            transitionSpec = { fadeIn(tween(ZeroMotion.ms(if (reduced) 150 else 220))) togetherWith fadeOut(tween(ZeroMotion.ms(if (reduced) 150 else 120))) },
            label = "stage",
        ) { t ->
            Text(
                t,
                style = MaterialTheme.typography.bodyMedium,
                color = if (conn is ConnState.Failed) c.err else c.muted,
                textAlign = TextAlign.Center,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (conn is ConnState.Failed) {
            Spacer(Modifier.height(12.dp))
            ZeroChip(
                text = stringResource(if (conn.reason == FailReason.VpnPermission) R.string.action_grant_permission else R.string.action_try_again),
                onClick = onRetry,
                icon = ZeroIcons.Refresh,
            )
        }
    }
}

@Composable
private fun ServerCard(state: HomeState, onClick: () -> Unit) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    val conn = state.conn
    val connected = (conn as? ConnState.Connected)?.server
    val title: String
    val subtitle: String
    var country = ""
    var badge: String? = null
    var delay = -1
    when {
        connected != null -> {
            country = connected.country
            title = countryLabel(context, connected.country, locale)
            delay = conn.delayMs
            badge = kindLabel(context, connected.kind)
            subtitle = if (state.target == ConnectTarget.Fastest) stringResource(R.string.server_fastest_picked) else serverTitle(context, connected, locale)
        }
        state.target is ConnectTarget.Country -> {
            country = state.target.code
            title = countryLabel(context, country, locale)
            subtitle = stringResource(R.string.server_country_best)
            delay = state.targetCountryDelay
        }
        state.target is ConnectTarget.Specific && state.targetServer != null -> {
            val s = state.targetServer
            country = s.country
            title = serverTitle(context, s, locale)
            subtitle = countryLabel(context, s.country, locale)
            delay = s.delayMs
            badge = kindLabel(context, s.kind)
        }
        else -> {
            title = stringResource(R.string.server_fastest)
            subtitle = stringResource(R.string.server_fastest_hint)
        }
    }
    val cardLabel = stringResource(R.string.server_card_action)
    ZeroCard(onClick = onClick, onClickLabel = cardLabel, padding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp, vertical = 14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (country.isEmpty() && connected == null) IconBadge(ZeroIcons.Bolt, size = 44.dp) else FlagBadge(country, size = 44.dp)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        title,
                        style = MaterialTheme.typography.titleMedium,
                        color = c.text,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (badge != null) {
                        Spacer(Modifier.width(8.dp))
                        Badge(badge, c.info)
                    }
                }
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.muted, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            if (delay >= 0) {
                Spacer(Modifier.width(8.dp))
                Text(
                    formatDelay(context, delay, locale),
                    style = MaterialTheme.typography.labelLarge,
                    color = c.delayColor(delay),
                    maxLines = 1,
                )
            }
            Spacer(Modifier.width(4.dp))
            Icon(ZeroIcons.ChevronEnd, null, tint = c.muted, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun StatsCard(stats: TrafficStats, since: Long, now: Long) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    ZeroCard(padding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RateBlock(ZeroIcons.ArrowDown, stringResource(R.string.stats_download), formatRate(context, stats.downRate, locale), c.ok, Modifier.weight(1f))
            RateBlock(ZeroIcons.ArrowUp, stringResource(R.string.stats_upload), formatRate(context, stats.upRate, locale), c.info, Modifier.weight(1f))
            SessionTimer(since, now)
        }
        Spacer(Modifier.height(12.dp))
        Sparkline(
            down = stats.downHistory,
            up = stats.upHistory,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .clearAndSetSemantics { },
        )
    }
}

@Composable
private fun RateBlock(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, rate: com.zeronet.mobile.ui.util.Rate, tint: Color, modifier: Modifier) {
    val c = ZeroTheme.colors
    val description = "$label ${rate.number} ${rate.unit}"
    Column(modifier.semantics(mergeDescendants = true) { contentDescription = description }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = c.muted, maxLines = 1)
        }
        Row(verticalAlignment = Alignment.Bottom) {
            Text(rate.number, style = MaterialTheme.typography.titleLarge, color = c.text, maxLines = 1)
            Spacer(Modifier.width(4.dp))
            Text(rate.unit, style = MaterialTheme.typography.labelMedium, color = c.muted, maxLines = 1, modifier = Modifier.padding(bottom = 4.dp))
        }
    }
}

/** Session time since [since], ticking once a second (this small composable is the only thing that recomposes). */
@Composable
private fun SessionTimer(since: Long, pinnedNow: Long) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val now = remember { mutableLongStateOf(if (pinnedNow > 0) pinnedNow else System.currentTimeMillis()) }
    if (pinnedNow <= 0) {
        // Ticks only while the screen is resumed: no wake-ups in the background.
        val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
        LaunchedEffect(since, lifecycle) {
            lifecycle.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.RESUMED) {
                while (true) {
                    now.longValue = System.currentTimeMillis()
                    delay(1000L - (now.longValue % 1000L))
                }
            }
        }
    }
    val label = stringResource(R.string.stats_session)
    val value = formatDuration(now.longValue - since, locale)
    Column(horizontalAlignment = Alignment.End, modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = "$label $value" }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(ZeroIcons.Clock, null, tint = c.muted, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = c.muted, maxLines = 1)
        }
        Text(value, style = MaterialTheme.typography.titleLarge.copy(letterSpacing = latinTracking(0.02)), color = c.text, maxLines = 1)
    }
}

/**
 * The last 60 seconds of throughput. The path is rebuilt only when a new
 * sample arrives (once a second), never per frame.
 */
@Composable
fun Sparkline(down: List<Long>, up: List<Long>, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    Box(
        modifier.drawWithCache {
            val max = (maxOf(down.maxOrNull() ?: 0L, up.maxOrNull() ?: 0L)).coerceAtLeast(1L).toFloat()
            fun build(values: List<Long>, fill: Boolean): androidx.compose.ui.graphics.Path {
                val p = androidx.compose.ui.graphics.Path()
                if (values.isEmpty()) return p
                val n = 60
                val step = size.width / (n - 1)
                val start = n - values.size
                values.forEachIndexed { i, v ->
                    val x = (start + i) * step
                    val y = size.height - (v / max) * (size.height - 4.dp.toPx()) - 2.dp.toPx()
                    if (i == 0) p.moveTo(x, y) else p.lineTo(x, y)
                }
                if (fill) {
                    p.lineTo(size.width, size.height)
                    p.lineTo(start * step, size.height)
                    p.close()
                }
                return p
            }
            val downLine = build(down, false)
            val downFill = build(down, true)
            val upLine = build(up, false)
            val fillBrush = Brush.verticalGradient(listOf(c.ok.copy(alpha = 0.28f), c.ok.copy(alpha = 0f)))
            val stroke = androidx.compose.ui.graphics.drawscope.Stroke(2.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round, join = androidx.compose.ui.graphics.StrokeJoin.Round)
            val thin = androidx.compose.ui.graphics.drawscope.Stroke(1.5.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round, join = androidx.compose.ui.graphics.StrokeJoin.Round)
            val baseline = 1.dp.toPx()
            onDrawBehind {
                drawRect(c.hairline, topLeft = Offset(0f, size.height - baseline), size = androidx.compose.ui.geometry.Size(size.width, baseline))
                drawPath(downFill, fillBrush)
                drawPath(upLine, c.info.copy(alpha = 0.7f), style = thin)
                drawPath(downLine, c.ok, style = stroke)
            }
        },
    )
}

/**
 * A low-contrast gradient field whose hue follows the connection:
 * neutral → accent → ok. It is deliberately still: a full-screen layer that
 * moves forces the blurred bars to redraw every frame.
 */
@Composable
private fun StateBackdrop(phase: OrbPhase, gaming: Boolean) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val target = when (phase) {
        OrbPhase.Idle -> c.muted
        OrbPhase.Busy -> c.accent
        OrbPhase.Connected -> c.ok
        OrbPhase.Failed -> c.err
    }
    val hue by animateColorAsState(target, tween(ZeroMotion.ms(if (reduced) 150 else 900)), label = "backdropHue")
    val strength = if (c.isDark) 0.16f else 0.10f
    Box(
        Modifier
            .fillMaxSize()
            .drawWithCache {
                val h = hue
                val r = size.maxDimension * 0.75f
                val a = Brush.radialGradient(listOf(h.copy(alpha = strength), Color.Transparent), center = Offset(size.width * 0.5f, size.height * 0.30f), radius = r)
                val b = Brush.radialGradient(listOf(h.copy(alpha = strength * 0.55f), Color.Transparent), center = Offset(size.width * 0.15f, size.height * 0.85f), radius = r * 0.8f)
                onDrawBehind {
                    drawRect(a)
                    drawRect(b)
                }
            },
    )
    // Gaming: a neon perspective floor rolling toward the viewer.
    val floor = remember { androidx.compose.animation.core.Animatable(if (gaming) 1f else 0f) }
    LaunchedEffect(gaming, reduced) {
        floor.animateTo(if (gaming) 1f else 0f, tween(ZeroMotion.ms(if (reduced) 150 else 900)))
    }
    if (gaming || floor.value > 0.001f) {
        val clock = rememberAmbientClock(gaming && !reduced)
        Box(
            Modifier
                .fillMaxSize()
                .drawWithCache {
                    val thin = 1.dp.toPx()
                    onDrawBehind {
                        val shown = floor.value
                        val horizon = size.height * 0.60f
                        val bottom = size.height
                        val vanishX = size.width / 2f
                        val depth = bottom - horizon
                        val lineColor = c.accentHot
                        // Horizon glow.
                        drawRect(
                            Brush.verticalGradient(
                                0f to Color.Transparent,
                                0.5f to lineColor.copy(alpha = 0.22f * shown),
                                1f to Color.Transparent,
                                startY = horizon - 40.dp.toPx(),
                                endY = horizon + 40.dp.toPx(),
                            ),
                            topLeft = Offset(0f, horizon - 40.dp.toPx()),
                            size = androidx.compose.ui.geometry.Size(size.width, 80.dp.toPx()),
                        )
                        // Rows: evenly spaced in depth, projected, scrolling toward the viewer.
                        val scroll = (clock.floatValue / 1400f) % 1f
                        for (k in 0 until 14) {
                            val z = 1f + (k + 1f - scroll) * 0.9f
                            val y = horizon + depth / z
                            if (y > bottom) continue
                            val fade = ((y - horizon) / depth).coerceIn(0f, 1f)
                            drawLine(lineColor.copy(alpha = 0.40f * fade * shown), Offset(0f, y), Offset(size.width, y), strokeWidth = thin)
                        }
                        // Columns converging on the vanishing point.
                        for (k in -10..10) {
                            val xBottom = vanishX + k * size.width * 0.16f
                            drawLine(
                                Brush.verticalGradient(
                                    0f to Color.Transparent,
                                    1f to c.accent.copy(alpha = 0.45f * shown),
                                    startY = horizon,
                                    endY = bottom,
                                ),
                                Offset(vanishX + k * size.width * 0.012f, horizon),
                                Offset(xBottom, bottom),
                                strokeWidth = thin,
                            )
                        }
                    }
                },
        )
    }
}
