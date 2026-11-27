package com.zeronet.mobile.service

import com.zeronet.mobile.service.TunWatch.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class TunWatchTest {
    @Test fun a_tunnel_that_is_there_is_fine() {
        val watch = TunWatch()
        repeat(10) { assertEquals(Verdict.Fine, watch.observe(false, it * 1000L)) }
    }

    @Test fun one_lost_sample_is_not_believed() {
        val watch = TunWatch()
        assertEquals(Verdict.Fine, watch.observe(true, 0))
        assertEquals(Verdict.Fine, watch.observe(false, 1000))
        assertEquals(Verdict.Fine, watch.observe(true, 2000))
    }

    @Test fun a_loss_that_lasts_is_recovered() {
        val watch = TunWatch()
        assertEquals(Verdict.Fine, watch.observe(true, 0))
        assertEquals(Verdict.Recover, watch.observe(true, 1000))
    }

    @Test fun it_gives_up_when_the_interface_keeps_closing() {
        val watch = TunWatch(giveUpAfter = 3, windowMs = 120_000)
        var now = 0L
        val verdicts = List(4) {
            watch.observe(true, now); now += 1000
            watch.observe(true, now).also { now += 1000 }
        }
        assertEquals(listOf(Verdict.Recover, Verdict.Recover, Verdict.Recover, Verdict.GiveUp), verdicts)
    }

    @Test fun old_recoveries_are_forgotten() {
        val watch = TunWatch(giveUpAfter = 1, windowMs = 60_000)
        watch.observe(true, 0)
        assertEquals(Verdict.Recover, watch.observe(true, 1000))
        watch.observe(true, 10_000)
        assertEquals(Verdict.GiveUp, watch.observe(true, 11_000))
        watch.observe(true, 100_000)
        assertEquals(Verdict.Recover, watch.observe(true, 101_000))
    }

    @Test fun a_new_connection_starts_clean() {
        val watch = TunWatch(giveUpAfter = 1)
        watch.observe(true, 0)
        assertEquals(Verdict.Recover, watch.observe(true, 1000))
        watch.reset()
        watch.observe(true, 2000)
        assertEquals(Verdict.Recover, watch.observe(true, 3000))
    }
}
