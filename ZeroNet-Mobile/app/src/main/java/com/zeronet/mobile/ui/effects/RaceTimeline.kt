package com.zeronet.mobile.ui.effects

import com.zeronet.mobile.model.LaneFail
import com.zeronet.mobile.model.LaneOutcome
import com.zeronet.mobile.model.RaceState
import kotlin.math.exp

/**
 * The route race as a timeline a screen can play. The race is real: the core
 * started the routes a moment apart and recorded when each one finished. A
 * race is usually over before the screen hears of it, so the screen replays it
 * from those times, slowed down enough to follow; nothing here is invented.
 *
 * Pure functions of the report and a time, so a frame can be tested.
 */
object RaceTimeline {
    enum class Phase { Waiting, Trying, Won, Lost, Skipped }

    /** What to draw for one route at one moment. [progress] is how far along its track it is. */
    data class LaneView(
        val route: String,
        val phase: Phase,
        val progress: Float,
        val fail: LaneFail?,
        /** When it finished, in race time, once it has. */
        val endedMs: Int,
    )

    /** How long a route is drawn taking to reach the end of its track when nothing answers. */
    private const val TRACK_MS = 1500f

    /** A route that is still trying gets this far along its track, never all the way. */
    private const val TRYING_CAP = 0.92f

    /** The time a won route takes to fill the rest of its track. */
    private const val FILL_MS = 260

    /** The time the whole race spans, in race milliseconds. */
    fun span(race: RaceState): Int =
        race.lanes.maxOfOrNull { lane ->
            when (lane.outcome) {
                LaneOutcome.Won, LaneOutcome.Lost -> lane.endMs
                LaneOutcome.Trying -> race.nowMs
                else -> 0
            }
        } ?: 0

    /**
     * How much a finished race is slowed when replayed, so the shortest race
     * still takes about [MIN_REPLAY_MS] to watch and a long one is not slowed.
     */
    fun replayScale(race: RaceState): Float {
        val span = span(race).coerceAtLeast(1)
        return (MIN_REPLAY_MS / span).coerceIn(1f, MAX_SLOWDOWN)
    }

    const val MIN_REPLAY_MS = 2400f
    const val MAX_SLOWDOWN = 8f

    private fun along(elapsedMs: Int): Float = TRYING_CAP * (1f - exp(-elapsedMs.coerceAtLeast(0) / TRACK_MS))

    /** The routes as they stood [atMs] into the race. */
    fun at(race: RaceState, atMs: Int): List<LaneView> = race.lanes.map { lane ->
        when (lane.outcome) {
            LaneOutcome.Skipped -> LaneView(lane.route, Phase.Skipped, 0f, null, 0)
            LaneOutcome.Waiting -> LaneView(lane.route, Phase.Waiting, 0f, null, 0)
            LaneOutcome.Trying -> when {
                atMs < lane.startMs -> LaneView(lane.route, Phase.Waiting, 0f, null, 0)
                else -> LaneView(lane.route, Phase.Trying, along(atMs - lane.startMs), null, 0)
            }
            LaneOutcome.Won -> when {
                atMs < lane.startMs -> LaneView(lane.route, Phase.Waiting, 0f, null, 0)
                atMs < lane.endMs -> LaneView(lane.route, Phase.Trying, along(atMs - lane.startMs), null, 0)
                else -> {
                    val from = along(lane.endMs - lane.startMs)
                    val fill = ((atMs - lane.endMs) / FILL_MS.toFloat()).coerceIn(0f, 1f)
                    LaneView(lane.route, Phase.Won, from + (1f - from) * fill, null, lane.endMs)
                }
            }
            LaneOutcome.Lost -> when {
                atMs < lane.startMs -> LaneView(lane.route, Phase.Waiting, 0f, null, 0)
                atMs < lane.endMs -> LaneView(lane.route, Phase.Trying, along(atMs - lane.startMs), null, 0)
                else -> LaneView(lane.route, Phase.Lost, along(lane.endMs - lane.startMs), lane.fail, lane.endMs)
            }
        }
    }

    /** Whether a route lost because the network stopped it, as opposed to another route being faster. */
    fun isBlocked(fail: LaneFail?): Boolean =
        fail == LaneFail.NoAnswer || fail == LaneFail.Refused || fail == LaneFail.NoTraffic

    /** What a finished race comes to, for the sentence under the lanes. */
    data class Verdict(val winner: String?, val blocked: Int)

    fun verdict(race: RaceState): Verdict = Verdict(
        winner = race.lanes.firstOrNull { it.outcome == LaneOutcome.Won }?.route,
        blocked = race.lanes.count { it.outcome == LaneOutcome.Lost && isBlocked(it.fail) },
    )
}
