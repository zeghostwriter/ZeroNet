package com.zeronet.mobile.ui.effects

import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.service.Diagnostics

/**
 * The connection test as a path: the phone, the provider, the filter and the
 * open internet, with the tunnel as a way around the filter. Each step of the
 * path gets a status from the checks that belong to it, and the first step
 * that fails says what is wrong in one plain sentence.
 *
 * Pure functions of the checks, so the picture and its words can be tested.
 */
object PathModel {
    /** The steps, in the order the direct path runs; [Bypass] is the tunnel around the filter. */
    enum class Step { Device, Provider, Filter, Bypass }

    /** What is wrong, in the words a person would use; the UI turns each into a sentence. */
    enum class Problem {
        None,
        NoNetwork,
        NoInternet,
        Redirected,
        FakeDns,
        NameFilter,
        NoServer,
    }

    private fun byId(checks: List<DiagCheck>, vararg ids: String): List<CheckStatus> =
        checks.filter { it.id in ids }.map { it.status }

    /** The worst of several statuses: a failure outranks a warning, which outranks unfinished work. */
    fun combine(statuses: List<CheckStatus>): CheckStatus {
        if (statuses.isEmpty()) return CheckStatus.Pending
        return when {
            CheckStatus.Bad in statuses -> CheckStatus.Bad
            CheckStatus.Warn in statuses -> CheckStatus.Warn
            CheckStatus.Running in statuses -> CheckStatus.Running
            CheckStatus.Pending in statuses -> CheckStatus.Pending
            CheckStatus.Ok in statuses -> CheckStatus.Ok
            else -> CheckStatus.Skipped
        }
    }

    fun status(step: Step, checks: List<DiagCheck>): CheckStatus = when (step) {
        Step.Device -> combine(byId(checks, Diagnostics.NETWORK))
        Step.Provider -> combine(byId(checks, Diagnostics.INTERNET, Diagnostics.DNS))
        Step.Filter -> combine(byId(checks, Diagnostics.TLS))
        Step.Bypass -> bypass(checks)
    }

    /**
     * Whether the way around the filter works: the live tunnel when there is
     * one, else the saved servers, of which one kind getting through is enough.
     */
    private fun bypass(checks: List<DiagCheck>): CheckStatus {
        byId(checks, Diagnostics.TUNNEL).firstOrNull()?.let { tunnel ->
            if (tunnel != CheckStatus.Skipped) return tunnel
        }
        val families = checks.filter { it.id.startsWith(Diagnostics.FAMILY_PREFIX) }.map { it.status }
        if (families.isEmpty()) return CheckStatus.Pending
        return when {
            families.any { it == CheckStatus.Ok || it == CheckStatus.Warn } -> CheckStatus.Ok
            families.any { it == CheckStatus.Running } -> CheckStatus.Running
            families.any { it == CheckStatus.Pending } -> CheckStatus.Pending
            families.all { it == CheckStatus.Skipped } -> CheckStatus.Skipped
            else -> CheckStatus.Bad
        }
    }

    /** Whether every check has finished. */
    fun finished(checks: List<DiagCheck>): Boolean =
        checks.isNotEmpty() && checks.none { it.status == CheckStatus.Pending || it.status == CheckStatus.Running }

    /**
     * The first thing wrong on the direct path, nearest the phone first: what
     * comes first is what stops the rest from mattering.
     */
    fun problem(checks: List<DiagCheck>): Problem {
        fun of(id: String) = checks.firstOrNull { it.id == id }?.status
        return when {
            of(Diagnostics.NETWORK) == CheckStatus.Bad -> Problem.NoNetwork
            of(Diagnostics.INTERNET) == CheckStatus.Bad -> Problem.NoInternet
            of(Diagnostics.INTERNET) == CheckStatus.Warn -> Problem.Redirected
            of(Diagnostics.DNS) == CheckStatus.Bad || of(Diagnostics.DNS) == CheckStatus.Warn -> Problem.FakeDns
            of(Diagnostics.TLS) == CheckStatus.Bad -> Problem.NameFilter
            status(Step.Bypass, checks) == CheckStatus.Bad -> Problem.NoServer
            else -> Problem.None
        }
    }

    /** The step the problem sits at, where the picture shows the break. */
    fun stepOf(problem: Problem): Step? = when (problem) {
        Problem.None -> null
        Problem.NoNetwork -> Step.Device
        Problem.NoInternet, Problem.Redirected, Problem.FakeDns -> Step.Provider
        Problem.NameFilter -> Step.Filter
        Problem.NoServer -> Step.Bypass
    }
}
