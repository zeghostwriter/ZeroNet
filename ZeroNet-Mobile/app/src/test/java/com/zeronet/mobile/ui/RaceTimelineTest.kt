package com.zeronet.mobile.ui

import com.zeronet.mobile.model.LaneFail
import com.zeronet.mobile.model.LaneOutcome
import com.zeronet.mobile.model.RaceLane
import com.zeronet.mobile.model.RaceState
import com.zeronet.mobile.service.Ipc
import com.zeronet.mobile.ui.effects.RaceTimeline
import com.zeronet.mobile.ui.effects.RaceTimeline.Phase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class RaceTimelineTest {
    /** WireGuard is dropped, QUIC is refused, HTTP/2 answers at 1.3 s. */
    private val race = RaceState(
        serial = 3, done = true, nowMs = 1500,
        lanes = listOf(
            RaceLane("wireguard", LaneOutcome.Lost, LaneFail.NoAnswer, 0, 900),
            RaceLane("masque-h3", LaneOutcome.Lost, LaneFail.Refused, 200, 260),
            RaceLane("masque-h2", LaneOutcome.Won, null, 400, 1300),
        ),
    )

    @Test fun routesStartWhenTheyStartedAndFinishWhenTheyFinished() {
        val early = RaceTimeline.at(race, 100)
        assertEquals(Phase.Trying, early[0].phase)
        assertEquals(Phase.Waiting, early[1].phase)
        assertEquals(Phase.Waiting, early[2].phase)

        val mid = RaceTimeline.at(race, 230)
        assertEquals(Phase.Trying, mid[1].phase)

        val later = RaceTimeline.at(race, 500)
        assertEquals(Phase.Lost, later[1].phase)
        assertEquals(LaneFail.Refused, later[1].fail)
        assertEquals(Phase.Trying, later[2].phase)

        val end = RaceTimeline.at(race, 1300 + 400)
        assertEquals(Phase.Won, end[2].phase)
        assertEquals(1f, end[2].progress, 1e-4f)
        assertEquals(Phase.Lost, end[0].phase)
    }

    @Test fun aRouteThatIsStillTryingNeverReachesTheEndOfItsTrack() {
        var last = 0f
        for (t in 0..20_000 step 250) {
            val p = RaceTimeline.at(race.copy(lanes = listOf(RaceLane("wireguard", LaneOutcome.Trying, null, 0, 0))), t)[0].progress
            assertTrue(p >= last)
            assertTrue(p < 1f)
            last = p
        }
    }

    @Test fun aWinnerFillsItsTrackAfterItAnswers() {
        val before = RaceTimeline.at(race, 1299)[2]
        val after = RaceTimeline.at(race, 1300 + 300)[2]
        assertTrue(before.progress < 1f)
        assertEquals(1f, after.progress, 1e-4f)
        // A loser stops where it fell and does not move again.
        assertEquals(RaceTimeline.at(race, 950)[0].progress, RaceTimeline.at(race, 5000)[0].progress, 1e-6f)
    }

    @Test fun aRouteThatWasNeverStartedStaysSkipped() {
        val quick = RaceState(
            serial = 1, done = true, nowMs = 300,
            lanes = listOf(
                RaceLane("wireguard", LaneOutcome.Won, null, 0, 250),
                RaceLane("masque-h3", LaneOutcome.Skipped, null, 200, 200),
            ),
        )
        assertEquals(Phase.Skipped, RaceTimeline.at(quick, 0)[1].phase)
        assertEquals(Phase.Skipped, RaceTimeline.at(quick, 9999)[1].phase)
    }

    @Test fun aQuickRaceIsSlowedDownToBeWatchableAndALongOneIsNot() {
        assertTrue(RaceTimeline.replayScale(race) > 1f)
        val slow = race.copy(lanes = listOf(RaceLane("wireguard", LaneOutcome.Won, null, 0, 6000)))
        assertEquals(1f, RaceTimeline.replayScale(slow), 1e-6f)
        val instant = race.copy(lanes = listOf(RaceLane("wireguard", LaneOutcome.Won, null, 0, 1)))
        assertEquals(RaceTimeline.MAX_SLOWDOWN, RaceTimeline.replayScale(instant), 1e-6f)
        assertEquals(0, RaceTimeline.span(RaceState()))
    }

    @Test fun theVerdictNamesTheWinnerAndCountsOnlyRoutesTheNetworkStopped() {
        val v = RaceTimeline.verdict(race)
        assertEquals("masque-h2", v.winner)
        assertEquals(2, v.blocked)
        val fast = RaceState(
            done = true,
            lanes = listOf(
                RaceLane("wireguard", LaneOutcome.Won, null, 0, 200),
                RaceLane("masque-h3", LaneOutcome.Lost, LaneFail.Beaten, 200, 250),
            ),
        )
        assertEquals(0, RaceTimeline.verdict(fast).blocked)
        assertNull(RaceTimeline.verdict(RaceState(lanes = listOf(RaceLane("wireguard", LaneOutcome.Lost, LaneFail.NoAnswer, 0, 6000)))).winner)
    }

    @Test fun theCoresJsonAndTheProcessBoundaryAgree() {
        val text = """{"serial":7,"done":true,"now":1300,"lanes":[
            {"r":"wireguard","s":"lost","f":"no_answer","a":0,"b":900},
            {"r":"masque-h2","s":"won","a":400,"b":1300}]}"""
        val parsed = Ipc.raceFromJson(JSONObject(text))
        assertEquals(2, parsed.lanes.size)
        assertEquals(LaneFail.NoAnswer, parsed.lanes[0].fail)
        assertEquals(LaneOutcome.Won, parsed.lanes[1].outcome)
        assertEquals(parsed, Ipc.raceFromJson(JSONObject(Ipc.raceToJson(parsed))))
        // An unknown word from a newer core is treated as a route that did not run, not a crash.
        val odd = Ipc.raceFromJson(JSONObject("""{"lanes":[{"r":"x","s":"from-the-future"}]}"""))
        assertEquals(LaneOutcome.Skipped, odd.lanes[0].outcome)
    }
}
