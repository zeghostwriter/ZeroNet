package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.home.MarsTrip
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MarsTripTest {
    @Test fun theWaitIsFourMinutesTwentySixSecondsAndTwentySixMilliseconds() {
        assertEquals((4 * 60 + 26) * 1000L + 26L, MarsTrip.IDLE_MS)
    }

    @Test fun theStayIsTwentyThreeSecondsBetweenTwoFastFlights() {
        assertEquals(23_000L, MarsTrip.STAY_MS)
        assertTrue(MarsTrip.FLIGHT_MS in 800L..2_000L)
        assertEquals(MarsTrip.FLIGHT_MS * 2 + MarsTrip.STAY_MS, MarsTrip.TOTAL_MS)
    }

    @Test fun earthLeavesMarsArrivesAndTheWholeThingIsOverAtTheEnd() {
        val start = MarsTrip.at(0)!!
        assertEquals(1f, start.earth, 1e-4f)
        assertEquals(0f, start.mars, 1e-4f)
        assertEquals(0f, start.warp, 1e-4f)
        val there = MarsTrip.at(MarsTrip.FLIGHT_MS + 5_000)!!
        assertEquals(0f, there.earth, 0f)
        assertEquals(1f, there.mars, 0f)
        val home = MarsTrip.at(MarsTrip.TOTAL_MS - 1)!!
        assertTrue(home.earth > 0.99f && home.mars < 0.01f)
        assertNull(MarsTrip.at(MarsTrip.TOTAL_MS))
        assertNull(MarsTrip.at(-1))
    }

    @Test fun theStarsStreakOnlyDuringAFlightAndPeakInTheMiddleOfIt() {
        val mid = MarsTrip.at(MarsTrip.FLIGHT_MS / 2)!!
        assertEquals(1f, mid.warp, 1e-4f)
        assertEquals(0f, MarsTrip.at(MarsTrip.FLIGHT_MS + 100)!!.warp, 0f)
        val back = MarsTrip.at(MarsTrip.FLIGHT_MS + MarsTrip.STAY_MS + MarsTrip.FLIGHT_MS / 2)!!
        assertEquals(1f, back.warp, 1e-3f)
    }

    @Test fun thePlanetsSwapWithoutBothBeingBigAtOnce() {
        for (ms in 0 until MarsTrip.TOTAL_MS step 50) {
            val f = MarsTrip.at(ms)!!
            assertTrue("$ms: ${f.earth} ${f.mars}", f.earth + f.mars <= 1.02f)
            assertTrue(f.earth in 0f..1f && f.mars in 0f..1f && f.warp in 0f..1f)
        }
    }

    @Test fun theWordsAppearOnTheWayThereAndGoOnTheWayBack() {
        assertFalse(MarsTrip.at(100)!!.words)
        assertTrue(MarsTrip.at(MarsTrip.FLIGHT_MS)!!.words)
        assertTrue(MarsTrip.at(MarsTrip.FLIGHT_MS + 12_000)!!.words)
        assertFalse(MarsTrip.at(MarsTrip.TOTAL_MS - 100)!!.words)
        assertNotNull(MarsTrip.at(MarsTrip.TOTAL_MS - 100))
    }

    @Test fun aTouchTurnsTheCameraHomeFromWhereverItIs() {
        // From Mars: straight into the flight home.
        assertEquals(MarsTrip.FLIGHT_MS + MarsTrip.STAY_MS, MarsTrip.afterTouch(MarsTrip.FLIGHT_MS + 3_000))
        // On the way there: back the same distance.
        val out = 400L
        val back = MarsTrip.afterTouch(out)
        assertEquals(MarsTrip.at(out)!!.earth, MarsTrip.at(back)!!.earth, 0.02f)
        // Already on the way home: unchanged.
        val homeward = MarsTrip.FLIGHT_MS + MarsTrip.STAY_MS + 300
        assertEquals(homeward, MarsTrip.afterTouch(homeward))
    }
}
