package com.zeronet.mobile.service

import com.zeronet.mobile.model.EvasionLevel

/**
 * The ways the recommended mode tries to connect.
 *
 * Every rung is a different way of getting a working server; the mode goes
 * down the ladder until one of them connects, so a network that blocks the
 * usual way still gets through by the next:
 *
 * 1. **known** – what worked on this network before, and what other people
 *    on it got through (a few seconds, no download);
 * 2. **search** – the public lists, tested as they are;
 * 3. **warp** – the user's own Cloudflare WARP account, when there is one;
 * 4. **disguise** – the lists again with every connection's first message
 *    split up and more fronted variants, for networks that read server names;
 * 5. **open** – nothing held back: any protocol, QUIC allowed.
 *
 * When there is a WARP account it goes **first**, before even the known
 * servers: WARP inside WARP exits abroad, so sites that refuse Iranian
 * addresses work, and it does not depend on public servers that come and go
 * (or see the traffic). Measured from Tehran it was also the quickest way
 * out. The other rungs are its fallback, in their usual order.
 *
 * A network remembers the rung that last worked, and the next connection
 * tries it straight after the first one instead of walking down again.
 */
object Ladder {
    /** What one rung changes about the way servers are found and used. */
    data class Rung(
        val id: String,
        /** Only test what is already known; no lists. */
        val known: Boolean = false,
        /** Test the user's own WARP account(s); no lists. */
        val warp: Boolean = false,
        /** Split the ClientHello whatever the setting says, or null for the setting. */
        val evasion: EvasionLevel? = null,
        /** Accept servers of any protocol and security, not only encrypted ones. */
        val relaxed: Boolean = false,
        /** Let QUIC through instead of blocking it. */
        val allowQuic: Boolean = false,
        /** How many fronted variants of past finds to test. */
        val fronts: Int = 18,
        /** Seconds the search may take. */
        val budgetSeconds: Int = 75,
    )

    const val KNOWN = 0
    const val SEARCH = 1
    const val WARP = 2
    const val DISGUISE = 3
    const val OPEN = 4

    val rungs: List<Rung> = listOf(
        Rung("known", known = true),
        Rung("search", budgetSeconds = 45),
        Rung("warp", warp = true),
        Rung("disguise", evasion = EvasionLevel.Strong, fronts = 36, budgetSeconds = 40),
        Rung("open", evasion = EvasionLevel.Strong, relaxed = true, allowQuic = true, fronts = 36, budgetSeconds = 40),
    )

    /**
     * The order to try the rungs in: WARP first when there is an account,
     * otherwise the quick known-servers rung; then the rung that last worked
     * here; then the rest from the top. [hasWarp] drops the WARP rung when
     * there is no account to try.
     */
    fun order(remembered: Int?, hasWarp: Boolean): List<Int> {
        val all = rungs.indices.filter { hasWarp || it != WARP }
        val first = if (hasWarp) listOf(WARP, KNOWN) else listOf(KNOWN)
        val next = listOfNotNull(remembered?.takeIf { it in all && it !in first })
        return (first + next + all).distinct()
    }

    /** The rung with this id, or null. */
    fun indexOf(id: String?): Int? = rungs.indexOfFirst { it.id == id }.takeIf { it >= 0 }
}
