package com.zeronet.mobile.ui.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.border
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.LaneFail
import com.zeronet.mobile.model.RaceState
import com.zeronet.mobile.ui.effects.RaceTimeline
import com.zeronet.mobile.ui.effects.RaceTimeline.Phase
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import kotlinx.coroutines.delay

/** How long a new race stays open before it folds into one line. */
private const val OPEN_MS = 9_000L

/**
 * How the last WARP connection was made: the routes it raced, drawn as lanes
 * that fill until one gets through, and why each of the others did not. It is
 * a replay of the core's own record, slowed to be followable, and it folds
 * into a single sentence a few seconds after a new race ends. Tap to open it.
 */
@Composable
fun RaceLanes(race: RaceState, modifier: Modifier = Modifier) {
    if (race.lanes.size < 2) return
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current

    // Race time shown, in milliseconds, advanced frame by frame: at real speed
    // while the race runs, and slowed while a finished one is replayed.
    var shown by remember { mutableFloatStateOf(if (race.done) Float.MAX_VALUE else race.nowMs.toFloat()) }
    var firstSerial by remember { mutableStateOf<Long?>(null) }
    LaunchedEffect(race.serial) {
        val first = firstSerial
        if (first == null) {
            firstSerial = race.serial
            return@LaunchedEffect
        }
        if (first != race.serial && !reduced) shown = 0f
    }
    LaunchedEffect(race, reduced) {
        if (reduced) {
            shown = Float.MAX_VALUE
            return@LaunchedEffect
        }
        val end = if (race.done) RaceTimeline.span(race) + 600f else race.nowMs + 1500f
        val rate = if (race.done) RaceTimeline.replayScale(race) else 1f
        var last = withFrameNanos { it }
        while (shown < end) {
            val now = withFrameNanos { it }
            shown = (shown + (now - last) / 1_000_000f * rate).coerceAtMost(end)
            last = now
        }
    }
    val views = RaceTimeline.at(race, shown.coerceAtMost(Int.MAX_VALUE.toFloat()).toInt())
    val finishedShowing = race.done && shown >= RaceTimeline.span(race) + 400f

    // Open for a new race, then fold; a tap opens it again.
    var open by remember { mutableStateOf(true) }
    LaunchedEffect(race.serial, finishedShowing) {
        if (finishedShowing) {
            delay(OPEN_MS)
            open = false
        } else {
            open = true
        }
    }

    val shape = RoundedCornerShape(16.dp)
    Column(
        modifier
            .fillMaxWidth()
            .background(c.surface, shape)
            .border(1.dp, c.hairline, shape)
            .clickable(role = Role.Button) { open = !open }
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .animateContentSize()
            .semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Text(
            stringResource(R.string.race_title),
            style = MaterialTheme.typography.labelMedium,
            color = c.muted,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            verdictText(race, finishedShowing),
            style = MaterialTheme.typography.bodyMedium,
            color = c.text,
        )
        AnimatedVisibility(open, enter = fadeIn(), exit = fadeOut()) {
            Column {
                Spacer(Modifier.height(10.dp))
                views.forEach { lane -> Lane(lane, reduced) }
            }
        }
    }
}

@Composable
private fun verdictText(race: RaceState, finishedShowing: Boolean): String {
    if (!race.done || !finishedShowing) return stringResource(R.string.race_live, race.lanes.size)
    val verdict = RaceTimeline.verdict(race)
    val winner = verdict.winner ?: return stringResource(R.string.race_failed)
    val name = routeName(winner)
    return if (verdict.blocked > 0) {
        stringResource(R.string.race_won_blocked, name)
    } else {
        stringResource(R.string.race_won_fastest, name)
    }
}

@Composable
private fun routeName(route: String): String = stringResource(
    when (route) {
        "wireguard" -> R.string.race_wireguard
        "masque-h2" -> R.string.race_h2
        else -> R.string.race_h3
    },
)

@Composable
private fun Lane(lane: RaceTimeline.LaneView, reduced: Boolean) {
    val c = ZeroTheme.colors
    val locale = currentLocale()
    val color = when (lane.phase) {
        Phase.Won -> c.ok
        Phase.Lost -> if (RaceTimeline.isBlocked(lane.fail)) c.err else c.muted
        Phase.Trying -> c.accent
        Phase.Waiting, Phase.Skipped -> c.border
    }
    val pulse by rememberInfiniteTransition(label = "runner").animateFloat(
        0.55f, 1f,
        infiniteRepeatable(tween(650), RepeatMode.Reverse),
        label = "runnerPulse",
    )
    val glow = if (lane.phase == Phase.Trying && !reduced) pulse else 1f
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            routeName(lane.route),
            style = MaterialTheme.typography.bodySmall,
            color = if (lane.phase == Phase.Skipped || lane.phase == Phase.Waiting) c.muted else c.text,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.width(92.dp),
        )
        Canvas(
            Modifier
                .weight(1f)
                .height(16.dp),
        ) {
            val y = size.height / 2f
            val stroke = 3.dp.toPx()
            val left = stroke
            val right = size.width - stroke
            drawLine(c.hairline, Offset(left, y), Offset(right, y), strokeWidth = stroke, cap = StrokeCap.Round)
            val x = left + (right - left) * lane.progress.coerceIn(0f, 1f)
            if (lane.phase != Phase.Waiting && lane.phase != Phase.Skipped) {
                drawLine(color.copy(alpha = if (lane.phase == Phase.Lost) 0.55f else 1f), Offset(left, y), Offset(x, y), strokeWidth = stroke, cap = StrokeCap.Round)
                when (lane.phase) {
                    Phase.Trying -> {
                        drawCircle(color.copy(alpha = 0.25f * glow), radius = 8.dp.toPx(), center = Offset(x, y))
                        drawCircle(color, radius = 4.dp.toPx(), center = Offset(x, y))
                    }
                    Phase.Won -> {
                        drawCircle(color.copy(alpha = 0.25f), radius = 8.dp.toPx(), center = Offset(x, y))
                        drawCircle(color, radius = 5.dp.toPx(), center = Offset(x, y))
                    }
                    Phase.Lost -> {
                        // A cross where it stopped: this is where the network cut it.
                        val a = 4.dp.toPx()
                        drawLine(color, Offset(x - a, y - a), Offset(x + a, y + a), strokeWidth = 2.dp.toPx(), cap = StrokeCap.Round)
                        drawLine(color, Offset(x - a, y + a), Offset(x + a, y - a), strokeWidth = 2.dp.toPx(), cap = StrokeCap.Round)
                    }
                    else -> {}
                }
            }
        }
        Text(
            laneResult(lane, locale),
            style = MaterialTheme.typography.bodySmall,
            color = if (lane.phase == Phase.Won) c.ok else c.muted,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.width(112.dp),
        )
    }
}

@Composable
private fun laneResult(lane: RaceTimeline.LaneView, locale: java.util.Locale): String = when (lane.phase) {
    Phase.Waiting -> stringResource(R.string.race_waiting)
    Phase.Trying -> stringResource(R.string.race_trying)
    Phase.Won -> stringResource(R.string.race_connected, Num.decimal(lane.endedMs / 1000.0, 1, locale))
    Phase.Skipped -> stringResource(R.string.race_not_needed)
    Phase.Lost -> stringResource(
        when (lane.fail) {
            LaneFail.NoAnswer -> R.string.race_no_answer
            LaneFail.Refused -> R.string.race_blocked
            LaneFail.NoTraffic -> R.string.race_no_traffic
            LaneFail.Beaten -> R.string.race_not_needed
            else -> R.string.race_failed_short
        },
    )
}
