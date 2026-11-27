package com.zeronet.mobile.ui.effects

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.ui.effects.PathModel.Problem
import com.zeronet.mobile.ui.effects.PathModel.Step
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlin.math.max
import kotlin.math.min

/**
 * Where the connection test found the connection stopped: the phone, the
 * provider, the filter and the open internet in a row, and the tunnel as an
 * arc over the filter. Each step lights up as its checks finish; a failed step
 * shows the line breaking where it broke, and one plain sentence underneath
 * says what that means. The technical findings stay in the rows below it.
 */
@Composable
fun PathMap(checks: List<DiagCheck>, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val statuses = Step.entries.map { PathModel.status(it, checks) }
    val finished = PathModel.finished(checks)
    val problem = if (finished) PathModel.problem(checks) else Problem.None

    // Each step plays a short settle when it stops being unfinished.
    val settle = remember { List(Step.entries.size) { Animatable(1f) } }
    Step.entries.forEachIndexed { i, _ ->
        val status = statuses[i]
        LaunchedEffect(status) {
            if (reduced || status == CheckStatus.Pending || status == CheckStatus.Running) {
                settle[i].snapTo(1f)
            } else {
                settle[i].snapTo(0f)
                settle[i].animateTo(1f, tween(ZeroMotion.ms(900), easing = LinearEasing))
            }
        }
    }
    val flow by rememberInfiniteTransition(label = "path").animateFloat(
        0f, 1f,
        infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Restart),
        label = "pathFlow",
    )
    val t = if (reduced) 0f else flow

    val summary = summary(statuses, finished, problem)
    Column(modifier.fillMaxWidth().semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite }) {
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(112.dp)
                .clearAndSetSemantics { contentDescription = summary },
        ) {
            val slot = size.width / 4f
            val nodeX = List(4) { slot * (it + 0.5f) }
            val lineY = size.height * 0.68f
            val nodeR = 17.dp.toPx()
            val colors = statuses.map { statusColor(it, c) }

            // The direct path: phone → provider → filter → internet.
            val direct = listOf(Step.Device, Step.Provider, Step.Filter)
            direct.forEachIndexed { i, step ->
                segment(
                    from = Offset(nodeX[i] + nodeR, lineY),
                    to = Offset(nodeX[i + 1] - nodeR, lineY),
                    status = statuses[step.ordinal],
                    color = colors[step.ordinal],
                    idle = c.border,
                    t = t,
                    settle = settle[step.ordinal].value,
                    reduced = reduced,
                )
            }

            // The way around the filter: an arc from the provider to the internet.
            bypass(
                from = Offset(nodeX[1], lineY - nodeR),
                to = Offset(nodeX[3], lineY - nodeR),
                peak = lineY - nodeR - size.height * 0.46f,
                status = statuses[Step.Bypass.ordinal],
                color = colors[Step.Bypass.ordinal],
                idle = c.border,
                t = t,
                settle = settle[Step.Bypass.ordinal].value,
                reduced = reduced,
            )

            // Nodes.
            val worldStatus = when {
                statuses[Step.Bypass.ordinal] == CheckStatus.Ok -> CheckStatus.Ok
                direct.all { statuses[it.ordinal] == CheckStatus.Ok || statuses[it.ordinal] == CheckStatus.Warn } && finished -> CheckStatus.Ok
                finished -> CheckStatus.Bad
                else -> CheckStatus.Pending
            }
            val nodeColors = listOf(
                colors[Step.Device.ordinal],
                colors[Step.Provider.ordinal],
                colors[Step.Filter.ordinal],
                statusColor(worldStatus, c),
            )
            for (i in 0 until 4) {
                drawCircle(c.surface, nodeR, Offset(nodeX[i], lineY))
                drawCircle(nodeColors[i].copy(alpha = 0.16f), nodeR, Offset(nodeX[i], lineY))
                drawCircle(nodeColors[i], nodeR, Offset(nodeX[i], lineY), style = Stroke(1.6.dp.toPx()))
            }
            phone(Offset(nodeX[0], lineY), nodeR, nodeColors[0])
            signal(Offset(nodeX[1], lineY), nodeR, nodeColors[1])
            wall(Offset(nodeX[2], lineY), nodeR, nodeColors[2])
            world(Offset(nodeX[3], lineY), nodeR, nodeColors[3])
        }
        Row(Modifier.fillMaxWidth()) {
            listOf(R.string.path_phone, R.string.path_provider, R.string.path_filter, R.string.path_world).forEach { label ->
                Text(
                    stringResource(label),
                    style = MaterialTheme.typography.labelSmall,
                    color = c.muted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        AnimatedContent(
            targetState = Triple(checks.isEmpty(), finished, problem),
            transitionSpec = { fadeIn(tween(ZeroMotion.ms(250))) togetherWith fadeOut(tween(ZeroMotion.ms(120))) },
            label = "pathWords",
        ) { (empty, done, what) ->
            Column {
                Text(
                    when {
                        empty -> stringResource(R.string.path_hint_idle)
                        !done -> stringResource(R.string.path_running)
                        else -> stringResource(headline(what))
                    },
                    style = MaterialTheme.typography.titleSmall,
                    color = if (done && what != Problem.None) c.text else c.text,
                )
                action(what, done)?.let { id ->
                    Spacer(Modifier.height(2.dp))
                    Text(stringResource(id), style = MaterialTheme.typography.bodyMedium, color = c.muted)
                }
            }
        }
        Spacer(Modifier.padding(bottom = 4.dp))
    }
}

/** The headline for a problem, in the words a person would use. */
fun headline(problem: Problem): Int = when (problem) {
    Problem.None -> R.string.path_ok_all
    Problem.NoNetwork -> R.string.path_no_network
    Problem.NoInternet -> R.string.path_no_internet
    Problem.Redirected -> R.string.path_redirected
    Problem.FakeDns -> R.string.path_dns
    Problem.NameFilter -> R.string.path_sni
    Problem.NoServer -> R.string.path_no_server
}

/** What to do or what ZeroNet does about it, or nothing to add. */
fun action(problem: Problem, finished: Boolean): Int? = if (!finished) null else when (problem) {
    Problem.None -> null
    Problem.NoNetwork, Problem.NoInternet -> R.string.path_do_offline
    Problem.Redirected -> R.string.path_do_redirect
    Problem.FakeDns -> R.string.path_do_dns
    Problem.NameFilter -> R.string.path_do_sni
    Problem.NoServer -> R.string.diag_verdict_none_work
}

@Composable
private fun summary(statuses: List<CheckStatus>, finished: Boolean, problem: Problem): String = when {
    statuses.all { it == CheckStatus.Pending } -> stringResource(R.string.path_hint_idle)
    !finished -> stringResource(R.string.path_running)
    else -> stringResource(headline(problem))
}

private fun statusColor(status: CheckStatus, c: com.zeronet.mobile.ui.theme.ZeroColors): Color = when (status) {
    CheckStatus.Ok -> c.ok
    CheckStatus.Warn -> c.warn
    CheckStatus.Bad -> c.err
    CheckStatus.Running -> c.accent
    CheckStatus.Pending, CheckStatus.Skipped -> c.border
}

// ---------------------------------------------------------------- segments

/**
 * One step of the direct path. Working: a solid line, with a light that runs
 * across once when the step settles. Failed: the line stops part-way, breaks,
 * and the rest is dashed, with a spark at the break that pops once.
 */
private fun DrawScope.segment(
    from: Offset,
    to: Offset,
    status: CheckStatus,
    color: Color,
    idle: Color,
    t: Float,
    settle: Float,
    reduced: Boolean,
) {
    val width = 3.dp.toPx()
    val length = to.x - from.x
    fun at(f: Float) = Offset(from.x + length * f, from.y)
    when (status) {
        CheckStatus.Pending, CheckStatus.Skipped -> dashed(from, to, idle, width)
        CheckStatus.Running -> {
            dashed(from, to, idle, width)
            // A short light running from the phone's side toward the internet's.
            val head = t
            val tail = max(0f, head - 0.28f)
            drawLine(color, at(tail), at(head), strokeWidth = width, cap = StrokeCap.Round)
            drawCircle(color, 4.dp.toPx(), at(head))
        }
        CheckStatus.Ok, CheckStatus.Warn -> {
            drawLine(color.copy(alpha = if (status == CheckStatus.Warn) 0.75f else 1f), from, to, strokeWidth = width, cap = StrokeCap.Round)
            if (!reduced && settle < 1f) {
                val head = settle
                drawLine(Color.White.copy(alpha = 0.85f * (1f - settle)), at(max(0f, head - 0.2f)), at(head), strokeWidth = width, cap = StrokeCap.Round)
            }
            if (status == CheckStatus.Warn) {
                // A warning is a line that flickers: short gaps along it.
                val gap = length / 9f
                for (k in 1..8 step 2) drawLine(idle.copy(alpha = 0.9f), at(k / 9f), Offset(from.x + gap * (k + 1), from.y), strokeWidth = width)
            }
        }
        CheckStatus.Bad -> {
            val breakAt = 0.58f
            val reach = if (reduced) breakAt else min(breakAt, settle * breakAt * 1.6f)
            drawLine(color, from, at(reach), strokeWidth = width, cap = StrokeCap.Round)
            // The rest lies dashed, the way the line would have gone.
            dashed(at(breakAt + 0.07f), to, idle, width)
            if (settle >= 0.55f || reduced) spark(at(breakAt + 0.035f), color, if (reduced) 1f else ((settle - 0.55f) / 0.45f).coerceIn(0f, 1f))
        }
    }
}

private fun DrawScope.dashed(from: Offset, to: Offset, color: Color, width: Float) {
    drawLine(
        color.copy(alpha = 0.8f), from, to, strokeWidth = width * 0.7f, cap = StrokeCap.Round,
        pathEffect = PathEffect.dashPathEffect(floatArrayOf(2.dp.toPx(), 7.dp.toPx())),
    )
}

/** A small burst where a line was cut: a cross that pops out and settles. */
private fun DrawScope.spark(at: Offset, color: Color, p: Float) {
    val pop = if (p < 0.5f) p / 0.5f * 1.35f else 1.35f - (p - 0.5f) / 0.5f * 0.35f
    val a = 5.dp.toPx() * pop
    drawCircle(color.copy(alpha = 0.22f * (1f - p * 0.4f)), 11.dp.toPx() * pop, at)
    drawLine(color, Offset(at.x - a, at.y - a), Offset(at.x + a, at.y + a), strokeWidth = 2.4.dp.toPx(), cap = StrokeCap.Round)
    drawLine(color, Offset(at.x - a, at.y + a), Offset(at.x + a, at.y - a), strokeWidth = 2.4.dp.toPx(), cap = StrokeCap.Round)
}

/**
 * The tunnel as an arc over the filter. Working: light dots run along it.
 * Failed: it stops short with a cross. Not run yet: a faint dashed arc.
 */
private fun DrawScope.bypass(
    from: Offset,
    to: Offset,
    peak: Float,
    status: CheckStatus,
    color: Color,
    idle: Color,
    t: Float,
    settle: Float,
    reduced: Boolean,
) {
    val width = 2.6.dp.toPx()
    val mid = Offset((from.x + to.x) / 2f, peak)
    // A quadratic curve through (from, mid-control, to), sampled.
    val control = Offset(mid.x, peak - (from.y - peak))
    fun point(f: Float): Offset {
        val u = 1f - f
        return Offset(
            u * u * from.x + 2f * u * f * control.x + f * f * to.x,
            u * u * from.y + 2f * u * f * control.y + f * f * to.y,
        )
    }
    fun trace(upTo: Float): Path = Path().apply {
        moveTo(from.x, from.y)
        val steps = 40
        for (i in 1..steps) {
            val p = point(upTo * i / steps)
            lineTo(p.x, p.y)
        }
    }
    when (status) {
        CheckStatus.Pending, CheckStatus.Skipped -> drawPath(
            trace(1f), idle.copy(alpha = 0.5f),
            style = Stroke(width * 0.7f, cap = StrokeCap.Round, pathEffect = PathEffect.dashPathEffect(floatArrayOf(2.dp.toPx(), 7.dp.toPx()))),
        )
        CheckStatus.Running -> {
            drawPath(
                trace(1f), color.copy(alpha = 0.45f),
                style = Stroke(width * 0.7f, cap = StrokeCap.Round, pathEffect = PathEffect.dashPathEffect(floatArrayOf(2.dp.toPx(), 7.dp.toPx()))),
            )
            drawCircle(color, 4.dp.toPx(), point(t))
        }
        CheckStatus.Ok, CheckStatus.Warn -> {
            val reach = if (reduced) 1f else min(1f, settle * 1.4f)
            drawPath(trace(reach), color.copy(alpha = 0.32f), style = Stroke(width * 3f, cap = StrokeCap.Round))
            drawPath(trace(reach), color, style = Stroke(width, cap = StrokeCap.Round))
            if (!reduced && reach >= 1f) {
                // Dots carried along it: traffic going around the filter.
                for (k in 0 until 3) {
                    val f = (t + k / 3f) % 1f
                    drawCircle(Color.White.copy(alpha = 0.9f), 2.2.dp.toPx(), point(f))
                }
            }
        }
        CheckStatus.Bad -> {
            val breakAt = 0.62f
            drawPath(trace(breakAt), color, style = Stroke(width, cap = StrokeCap.Round))
            drawPath(
                Path().apply {
                    val start = min(1f, breakAt + 0.08f)
                    val first = point(start)
                    moveTo(first.x, first.y)
                    for (i in 1..14) {
                        val p = point(start + (1f - start) * i / 14f)
                        lineTo(p.x, p.y)
                    }
                },
                idle.copy(alpha = 0.6f),
                style = Stroke(width * 0.7f, cap = StrokeCap.Round, pathEffect = PathEffect.dashPathEffect(floatArrayOf(2.dp.toPx(), 7.dp.toPx()))),
            )
            if (settle >= 0.4f || reduced) spark(point(breakAt + 0.04f), color, if (reduced) 1f else ((settle - 0.4f) / 0.6f).coerceIn(0f, 1f))
        }
    }
}

// ------------------------------------------------------------------- nodes

private fun DrawScope.phone(at: Offset, r: Float, color: Color) {
    val w = r * 0.62f
    val h = r * 1.02f
    drawRoundRect(color, Offset(at.x - w / 2f, at.y - h / 2f), Size(w, h), CornerRadius(w * 0.24f), style = Stroke(1.6.dp.toPx()))
    drawLine(color, Offset(at.x - w * 0.16f, at.y + h * 0.34f), Offset(at.x + w * 0.16f, at.y + h * 0.34f), strokeWidth = 1.6.dp.toPx(), cap = StrokeCap.Round)
}

private fun DrawScope.signal(at: Offset, r: Float, color: Color) {
    drawCircle(color, 2.2.dp.toPx(), Offset(at.x, at.y + r * 0.2f))
    for (k in 1..2) {
        val radius = r * (0.3f + 0.26f * k)
        val sweep = 70f
        val path = Path().apply {
            arcTo(
                androidx.compose.ui.geometry.Rect(at.x - radius, at.y + r * 0.2f - radius, at.x + radius, at.y + r * 0.2f + radius),
                -90f - sweep / 2f, sweep, true,
            )
        }
        drawPath(path, color, style = Stroke(1.6.dp.toPx(), cap = StrokeCap.Round))
    }
}

private fun DrawScope.wall(at: Offset, r: Float, color: Color) {
    val w = r * 1.05f
    val h = r * 0.9f
    val left = at.x - w / 2f
    val top = at.y - h / 2f
    val stroke = 1.5.dp.toPx()
    drawRoundRect(color, Offset(left, top), Size(w, h), CornerRadius(2.dp.toPx()), style = Stroke(stroke))
    for (row in 1..2) drawLine(color, Offset(left, top + h * row / 3f), Offset(left + w, top + h * row / 3f), strokeWidth = stroke)
    drawLine(color, Offset(at.x, top), Offset(at.x, top + h / 3f), strokeWidth = stroke)
    drawLine(color, Offset(left + w * 0.3f, top + h / 3f), Offset(left + w * 0.3f, top + h * 2f / 3f), strokeWidth = stroke)
    drawLine(color, Offset(left + w * 0.7f, top + h / 3f), Offset(left + w * 0.7f, top + h * 2f / 3f), strokeWidth = stroke)
    drawLine(color, Offset(at.x, top + h * 2f / 3f), Offset(at.x, top + h), strokeWidth = stroke)
}

private fun DrawScope.world(at: Offset, r: Float, color: Color) {
    val radius = r * 0.55f
    val stroke = Stroke(1.5.dp.toPx())
    drawCircle(color, radius, at, style = stroke)
    drawLine(color, Offset(at.x - radius, at.y), Offset(at.x + radius, at.y), strokeWidth = 1.5.dp.toPx())
    drawOval(color, Offset(at.x - radius * 0.45f, at.y - radius), Size(radius * 0.9f, radius * 2f), style = stroke)
}

