package com.zeronet.mobile.service

/**
 * Decides what to do when the core says its tunnel device is gone.
 *
 * The VPN interface can disappear while the engine still believes it is
 * connected: the system closes it, another VPN takes over, or a restart hands
 * over a descriptor that is already dead. The status-bar key goes out, and
 * without this the app would go on saying "connected". The core reports the
 * loss (`tun_lost` in its stats); this class turns that report, sampled once a
 * second, into an action:
 *
 * * a single sample is not trusted, since a restart has a moment where the old
 *   device is closed and the new one not yet adopted, so the loss must last
 *   [confirmAfter] samples in a row;
 * * a confirmed loss is answered by rebuilding the interface ([Verdict.Recover]);
 * * if that has already been done [giveUpAfter] times inside [windowMs], the
 *   interface keeps closing for a reason a restart will not fix, and the honest
 *   thing is to stop and say so ([Verdict.GiveUp]) rather than loop.
 */
class TunWatch(
    private val confirmAfter: Int = 2,
    private val giveUpAfter: Int = 3,
    private val windowMs: Long = 120_000L,
) {
    enum class Verdict { Fine, Recover, GiveUp }

    private var lostSamples = 0
    private val recoveries = ArrayDeque<Long>()

    /** One sample of the core's report, taken at [now] (epoch milliseconds). */
    fun observe(lost: Boolean, now: Long): Verdict {
        if (!lost) {
            lostSamples = 0
            return Verdict.Fine
        }
        lostSamples++
        if (lostSamples < confirmAfter) return Verdict.Fine
        lostSamples = 0
        while (recoveries.isNotEmpty() && now - recoveries.first() > windowMs) recoveries.removeFirst()
        if (recoveries.size >= giveUpAfter) return Verdict.GiveUp
        recoveries.addLast(now)
        return Verdict.Recover
    }

    /** A fresh connection starts with a clean record. */
    fun reset() {
        lostSamples = 0
        recoveries.clear()
    }
}
