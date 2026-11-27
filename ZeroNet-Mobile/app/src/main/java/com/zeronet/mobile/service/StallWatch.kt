package com.zeronet.mobile.service

/**
 * Tells a stalled tunnel from an idle phone, one second at a time.
 *
 * A stalled tunnel looks like this: apps keep sending (a page load, a retry,
 * a message) and **not one byte** comes back. An idle phone looks different:
 * nothing is sent, or whatever is sent (a keep-alive, a chat ping) gets its
 * small answer. Counting quiet time alone cannot tell the two apart, because
 * apps hold connections open while the person reads, so the old rule
 * switched servers — and dropped every connection — whenever someone paused
 * for half a minute.
 *
 * So only seconds that sent something and got nothing back count, any byte
 * back clears the count, and silent seconds neither count nor clear it. The
 * tunnel is called stalled after [askingSeconds] such seconds.
 */
class StallWatch(private val askingSeconds: Int = 10) {
    private var unanswered = 0

    /**
     * One second of traffic: bytes the apps sent ([up]) and received
     * ([down]), and how many connections are open. Returns true once, when
     * the stall is established; the count then starts over.
     */
    fun observe(up: Long, down: Long, sessions: Int): Boolean {
        when {
            sessions == 0 || down > 0 -> unanswered = 0
            up > 0 -> unanswered++
        }
        if (unanswered >= askingSeconds) {
            unanswered = 0
            return true
        }
        return false
    }

    fun reset() {
        unanswered = 0
    }
}
