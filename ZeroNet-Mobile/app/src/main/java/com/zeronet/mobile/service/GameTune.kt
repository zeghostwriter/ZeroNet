package com.zeronet.mobile.service

import kotlin.math.abs

/**
 * Picking the server for a game by how steady it is, not only how quick.
 *
 * One ping says little: a server that answers in 60 ms once and 300 ms the
 * next time is worse for a match than one that always takes 90. So the
 * servers are timed several times, and each is scored by its typical delay
 * plus what its delays wander (twice), plus a heavy charge for every attempt
 * that got no answer at all. The lowest score wins.
 */
object GameTune {
    /** Charge, in milliseconds, for each attempt that got no answer. */
    const val LOSS_PENALTY_MS = 400.0

    /** A change of server has to be at least this much better to be worth the switch. */
    const val WORTH_SWITCHING = 0.85

    /**
     * The score for one server from its delays in ms, with a negative number
     * for an attempt that got no answer. Lower is better; a server that never
     * answered scores [Double.MAX_VALUE].
     */
    fun score(delays: List<Int>): Double {
        val answered = delays.filter { it >= 0 }.sorted()
        if (answered.isEmpty()) return Double.MAX_VALUE
        val median = answered[answered.size / 2].toDouble()
        // The mean, not the median, of the deviations: one spike is what ruins a match.
        val jitter = answered.map { abs(it - median) }.average()
        val lost = delays.size - answered.size
        return median + 2.0 * jitter + LOSS_PENALTY_MS * lost / delays.size * 3.0
    }

    /**
     * The key to use: the best-scoring server, unless [current] is nearly as
     * good ([WORTH_SWITCHING]), in which case it stays where it is.
     */
    fun pick(results: Map<String, List<Int>>, current: String?): String? {
        val scored = results.mapValues { score(it.value) }.filterValues { it < Double.MAX_VALUE }
        val best = scored.minByOrNull { it.value } ?: return null
        val now = current?.let { scored[it] }
        return if (now != null && best.value >= now * WORTH_SWITCHING) current else best.key
    }
}
