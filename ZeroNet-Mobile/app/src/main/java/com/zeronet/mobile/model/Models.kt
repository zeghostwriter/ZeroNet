package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONObject

/**
 * A config the app can connect through. Built from Zray's LinkInfo (see
 * docs/native-contract.md) plus what the app has learned about it.
 */
@Immutable
data class Server(
    val key: String,
    val link: String,
    val name: String,
    val protocol: String,
    val transport: String,
    val security: String,
    val host: String,
    val port: Int,
    /** ISO-3166 alpha-2, upper case, or "" when unknown. */
    val country: String,
    val source: String,
    val favorite: Boolean = false,
    /** The user ruled this server out of automatic selection; it stays in the
     *  list and can be connected to by hand, but discovery/switching skip it. */
    val excluded: Boolean = false,
    /** Last measured real delay in ms, or -1 when the last test failed / never tested. */
    val delayMs: Int = -1,
    val lastTestedAt: Long = 0,
    val aliveCount: Int = 0,
    val failCount: Int = 0,
    /** Why the last test failed, as the core reported it; null after a success. */
    val lastError: String? = null,
    /** For a WARP account, the fingerprint of its keys, which is drawn as a small picture; "" for every other link. */
    val fingerprint: String = "",
) {
    val isUser: Boolean get() = source == SOURCE_USER || source.startsWith(SOURCE_SUB_PREFIX)

    /**
     * Short, jargon-free label for the class of config: shown as a badge.
     * The same families discovery interleaves by (the core's `LinkClass`),
     * plus QUIC, because they fail differently under filtering: a split
     * XHTTP path is the hardest to classify, REALITY impersonates a real
     * site, CDN-fronted configs hide behind Cloudflare's addresses, and QUIC
     * lives or dies with UDP.
     */
    val kind: ServerKind
        get() = when {
            protocol == "hysteria2" || protocol == "tuic" -> ServerKind.Quic
            transport == "xhttp" && hasParam(link, "extra") -> ServerKind.Split
            security == "reality" -> ServerKind.Direct
            transport in CDN_TRANSPORTS && security == "tls" -> ServerKind.Cdn
            else -> ServerKind.Other
        }

    /** Found working by other ZeroNet users (the crowd rankings), not just listed in a feed. */
    val crowdVerified: Boolean get() = source == SOURCE_FEED_PREFIX + "crowd"

    companion object {
        const val SOURCE_USER = "user"
        const val SOURCE_SUB_PREFIX = "sub:"
        const val SOURCE_FEED_PREFIX = "feed:"
        private val CDN_TRANSPORTS = setOf("ws", "grpc", "xhttp", "httpupgrade")

        /** Whether the link's query has a non-empty [name] parameter (as the core's `link_has_param`). */
        private fun hasParam(link: String, name: String): Boolean {
            val query = link.substringBefore('#').substringAfter('?', "")
            if (query.isEmpty()) return false
            return query.split('&').any { pair ->
                pair.substringBefore('=').equals(name, ignoreCase = true) && pair.substringAfter('=', "").isNotBlank()
            }
        }

        fun fromLinkInfo(info: JSONObject, source: String): Server = Server(
            key = info.optString("key"),
            link = info.optString("link"),
            name = info.optString("name").ifBlank { info.optString("host") },
            protocol = info.optString("protocol"),
            transport = info.optString("transport"),
            security = info.optString("security"),
            host = info.optString("host"),
            port = info.optInt("port"),
            country = info.optString("country").uppercase(),
            source = source,
            fingerprint = info.optString("fp"),
        )
    }
}

enum class ServerKind { Split, Direct, Cdn, Quic, Other }

/** What the user asked to connect to. */
sealed interface ConnectTarget {
    /** Discover and pick the best config automatically. */
    data object Fastest : ConnectTarget
    data class Country(val code: String) : ConnectTarget
    /** One config the user chose: used as is, never swapped for another. */
    data class Specific(val key: String) : ConnectTarget
    /**
     * The user's own subscriptions, one or several: the engine searches and
     * switches only between their configs. [ids] is never empty, sorted and
     * without repeats, so the same choice always compares and saves the same.
     */
    data class Subscription(val ids: List<String>) : ConnectTarget {
        constructor(id: String) : this(listOf(id))

        companion object {
            /** The target for [ids], or null when none is left. */
            fun of(ids: Collection<String>): Subscription? =
                ids.map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted().takeIf { it.isNotEmpty() }?.let(::Subscription)
        }
    }

    fun encode(): String = when (this) {
        Fastest -> "fastest"
        is Country -> "country:$code"
        is Specific -> "server:$key"
        is Subscription -> "sub:" + ids.joinToString(",")
    }

    companion object {
        fun decode(value: String?): ConnectTarget = when {
            value == null || value == "fastest" -> Fastest
            value.startsWith("country:") -> Country(value.removePrefix("country:"))
            value.startsWith("server:") -> Specific(value.removePrefix("server:"))
            // One id (saved before several could be chosen) or several, comma-separated.
            value.startsWith("sub:") -> Subscription.of(value.removePrefix("sub:").split(',')) ?: Fastest
            else -> Fastest
        }
    }
}

enum class DiscoveryStage { History, Fetch, Parse, Tcp, Real }

@Immutable
data class DiscoveryProgress(
    val stage: DiscoveryStage = DiscoveryStage.History,
    val candidates: Int = 0,
    val tcpDone: Int = 0,
    val tcpOpen: Int = 0,
    val realDone: Int = 0,
    val alive: Int = 0,
    /** The way being tried when the mode has several (see `Ladder`): its id, or "" when there is one. */
    val method: String = "",
)

/** The connection as the UI shows it. */
@Immutable
sealed interface ConnState {
    data object Idle : ConnState

    /** Looking for a working config. */
    data class Searching(val progress: DiscoveryProgress) : ConnState

    /** A config was picked; the tunnel is coming up. */
    data class Connecting(val server: Server?) : ConnState

    data class Connected(
        val server: Server,
        val since: Long,
        val delayMs: Int,
        /** How many working configs are balanced behind this connection. */
        val pool: Int,
    ) : ConnState

    /** The active config died; the engine is switching or searching again. */
    data class Reconnecting(val reason: String) : ConnState

    data class Failed(val reason: FailReason, val detail: String) : ConnState

    data object Disconnecting : ConnState

    val isActive: Boolean
        get() = this is Searching || this is Connecting || this is Connected || this is Reconnecting
}

enum class FailReason {
    NoWorkingServer,
    NoNetwork,
    VpnPermission,
    VpnRevoked,
    CoreError,
    ServerUnavailable,
}

@Immutable
data class TrafficStats(
    /** Bytes per second, averaged over the last second. */
    val upRate: Long = 0,
    val downRate: Long = 0,
    val upTotal: Long = 0,
    val downTotal: Long = 0,
    /** Recent download rates (oldest first), one sample per second, max 60. */
    val downHistory: List<Long> = emptyList(),
    val upHistory: List<Long> = emptyList(),
    /** How the core handles Cloudflare CDN configs on this network: "",
     *  "unknown", "clear", "fragment", "ech" or "blocked". */
    val cdn: String = "",
)

@Immutable
data class ScanResult(val ip: String, val port: Int, val rttMs: Int)

@Immutable
data class ScanState(
    val running: Boolean = false,
    val scanned: Int = 0,
    val responsive: Int = 0,
    val total: Int = 0,
    val results: List<ScanResult> = emptyList(),
    val error: String? = null,
)

/** Result of importing pasted/shared text. */
@Immutable
data class ImportResult(val added: Int, val duplicates: Int, val rejected: Int, val error: String? = null)

/** LAN sharing endpoint shown to the user while connected. */
@Immutable
data class LanEndpoint(val address: String, val socksPort: Int, val httpPort: Int)

enum class CheckStatus { Pending, Running, Ok, Warn, Bad, Skipped }

/**
 * One line of the connection self-test. [id] names the check (the UI
 * translates it); [detail] is the short technical finding: numbers,
 * addresses, the error the network produced.
 */
@Immutable
data class DiagCheck(val id: String, val status: CheckStatus, val detail: String = "")

/** How one route of a WARP race ended, as the core reports it. */
enum class LaneOutcome { Waiting, Trying, Won, Lost, Skipped }

/** Why a route lost. */
enum class LaneFail { NoAnswer, Refused, NoTraffic, Beaten, Other }

/** One route in a race; times are milliseconds since the race began. */
@Immutable
data class RaceLane(
    /** `wireguard`, `masque-h2` or `masque-h3`. */
    val route: String,
    val outcome: LaneOutcome,
    val fail: LaneFail? = null,
    val startMs: Int = 0,
    val endMs: Int = 0,
)

/** The last route race of a WARP account: which routes tried, which won, and why the rest did not. */
@Immutable
data class RaceState(
    val serial: Long = 0,
    val done: Boolean = true,
    val nowMs: Int = 0,
    val lanes: List<RaceLane> = emptyList(),
)

/** Where a Cloudflare WARP account request stands. */
enum class WarpPhase { Idle, Working, Done, Failed }

/**
 * The WARP account request: the steps so far, and on success the fingerprint
 * of the new keys (their public halves, hashed), which the sheet reveals.
 */
@Immutable
data class WarpState(
    val phase: WarpPhase = WarpPhase.Idle,
    val steps: List<String> = emptyList(),
    val fingerprint: String = "",
    val servers: Int = 0,
    val route: String = "",
    val error: String = "",
)

@Immutable
data class Diagnosis(
    val running: Boolean = false,
    val checks: List<DiagCheck> = emptyList(),
    val finishedAt: Long = 0,
)
