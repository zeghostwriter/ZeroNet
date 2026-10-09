package com.zeronet.mobile.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StallWatchTest {
    private fun run(watch: StallWatch, seconds: List<Triple<Long, Long, Int>>): Int =
        seconds.count { (up, down, sessions) -> watch.observe(up, down, sessions) }

    @Test fun readingAPageWithConnectionsOpenIsNotAStall() {
        // A minute of nothing moving while the browser keeps its sockets.
        assertEquals(0, run(StallWatch(), List(60) { Triple(0L, 0L, 12) }))
    }

    @Test fun keepAlivesThatGetAnAnswerAreNotAStall() {
        // A chat app pinging every few seconds and hearing back each time.
        val seconds = List(60) { if (it % 5 == 0) Triple(40L, 40L, 3) else Triple(0L, 0L, 3) }
        assertEquals(0, run(StallWatch(), seconds))
    }

    @Test fun sendingWithNothingComingBackIsAStall() {
        val watch = StallWatch()
        repeat(9) { assertFalse(watch.observe(1_500, 0, 4)) }
        assertTrue(watch.observe(1_500, 0, 4))
        // Reported once, then counted afresh.
        assertFalse(watch.observe(1_500, 0, 4))
    }

    @Test fun quietSecondsInBetweenNeitherCountNorClear() {
        val watch = StallWatch()
        val seconds = List(30) { if (it % 3 == 0) Triple(800L, 0L, 2) else Triple(0L, 0L, 2) }
        assertEquals(1, run(watch, seconds))
    }

    @Test fun anyByteBackClearsTheCount() {
        val watch = StallWatch()
        repeat(9) { watch.observe(1_000, 0, 2) }
        assertFalse(watch.observe(1_000, 1, 2))
        repeat(9) { assertFalse(watch.observe(1_000, 0, 2)) }
    }

    @Test fun noOpenConnectionsMeansNothingToStall() {
        val watch = StallWatch()
        repeat(9) { watch.observe(1_000, 0, 2) }
        watch.observe(1_000, 0, 0)
        repeat(9) { assertFalse(watch.observe(1_000, 0, 2)) }
    }
}
