package com.zeronet.mobile.ui

import com.zeronet.mobile.model.CheckStatus.Bad
import com.zeronet.mobile.model.CheckStatus.Ok
import com.zeronet.mobile.model.CheckStatus.Pending
import com.zeronet.mobile.model.CheckStatus.Running
import com.zeronet.mobile.model.CheckStatus.Skipped
import com.zeronet.mobile.model.CheckStatus.Warn
import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.service.Diagnostics
import com.zeronet.mobile.ui.effects.PathModel
import com.zeronet.mobile.ui.effects.PathModel.Problem
import com.zeronet.mobile.ui.effects.PathModel.Step
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PathModelTest {
    private fun checks(
        network: CheckStatus = Ok,
        internet: CheckStatus = Ok,
        dns: CheckStatus = Ok,
        tls: CheckStatus = Ok,
        tunnel: CheckStatus? = null,
        families: List<CheckStatus> = emptyList(),
    ): List<DiagCheck> = buildList {
        add(DiagCheck(Diagnostics.NETWORK, network))
        add(DiagCheck(Diagnostics.INTERNET, internet))
        add(DiagCheck(Diagnostics.DNS, dns))
        add(DiagCheck(Diagnostics.TLS, tls))
        tunnel?.let { add(DiagCheck(Diagnostics.TUNNEL, it)) }
        families.forEachIndexed { i, s -> add(DiagCheck(Diagnostics.FAMILY_PREFIX + "kind$i", s)) }
    }

    @Test fun aStepTakesTheWorstOfItsChecks() {
        assertEquals(Bad, PathModel.combine(listOf(Ok, Bad, Warn)))
        assertEquals(Warn, PathModel.combine(listOf(Ok, Warn, Running)))
        assertEquals(Running, PathModel.combine(listOf(Ok, Running, Pending)))
        assertEquals(Pending, PathModel.combine(listOf(Ok, Pending)))
        assertEquals(Ok, PathModel.combine(listOf(Ok, Skipped)))
        assertEquals(Skipped, PathModel.combine(listOf(Skipped)))
        assertEquals(Pending, PathModel.combine(emptyList()))
    }

    @Test fun everythingWorkingMeansNothingIsWrong() {
        val all = checks(tunnel = null, families = listOf(Ok, Warn))
        assertEquals(Problem.None, PathModel.problem(all))
        assertNull(PathModel.stepOf(PathModel.problem(all)))
        assertEquals(Ok, PathModel.status(Step.Bypass, all))
    }

    @Test fun theProblemNearestThePhoneIsTheOneReported() {
        assertEquals(Problem.NoNetwork, PathModel.problem(checks(network = Bad, internet = Bad, dns = Bad)))
        assertEquals(Problem.NoInternet, PathModel.problem(checks(internet = Bad, dns = Bad, tls = Bad)))
        assertEquals(Problem.Redirected, PathModel.problem(checks(internet = Warn, dns = Bad)))
        assertEquals(Problem.FakeDns, PathModel.problem(checks(dns = Bad, tls = Bad)))
        assertEquals(Problem.FakeDns, PathModel.problem(checks(dns = Warn)))
        assertEquals(Problem.NameFilter, PathModel.problem(checks(tls = Bad)))
    }

    @Test fun aFilterThatTheTunnelGoesAroundIsStillTheProblemButTheBypassIsGreen() {
        val c = checks(tls = Bad, tunnel = Ok)
        assertEquals(Problem.NameFilter, PathModel.problem(c))
        assertEquals(Step.Filter, PathModel.stepOf(Problem.NameFilter))
        assertEquals(Bad, PathModel.status(Step.Filter, c))
        assertEquals(Ok, PathModel.status(Step.Bypass, c))
    }

    @Test fun noServerGettingThroughIsReportedWhenTheDirectPathIsFine() {
        val c = checks(families = listOf(Bad, Bad, Skipped))
        assertEquals(Problem.NoServer, PathModel.problem(c))
        assertEquals(Step.Bypass, PathModel.stepOf(Problem.NoServer))
        assertEquals(Problem.None, PathModel.problem(checks(families = listOf(Skipped, Skipped))))
    }

    @Test fun theLiveTunnelOutranksTheSavedServersWhenThereIsOne() {
        assertEquals(Bad, PathModel.status(Step.Bypass, checks(tunnel = Bad, families = listOf(Ok))))
        assertEquals(Ok, PathModel.status(Step.Bypass, checks(tunnel = Ok, families = listOf(Bad))))
        // A skipped tunnel check falls back to the saved servers.
        assertEquals(Ok, PathModel.status(Step.Bypass, checks(tunnel = Skipped, families = listOf(Ok))))
    }

    @Test fun anUnfinishedTestHasNoProblemYetAndIsNotFinished() {
        val running = checks(network = Ok, internet = Running, dns = Pending, tls = Pending, families = listOf(Pending))
        assertFalse(PathModel.finished(running))
        assertEquals(Problem.None, PathModel.problem(running))
        assertTrue(PathModel.finished(checks(families = listOf(Ok))))
        assertFalse(PathModel.finished(emptyList()))
    }
}
