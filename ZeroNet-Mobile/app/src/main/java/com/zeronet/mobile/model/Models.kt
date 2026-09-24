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
    /** Last measured real delay in ms, or -1 when the last test failed / never tested. */
    val delayMs: Int = -1,
    val lastTestedAt: Long = 0,
    val aliveCount: Int = 0,
    val failCount: Int = 0,
) {
    val isUser: Boolean get() = source == SOURCE_USER || source.startsWith(SOURCE_SUB_PREFIX)

    /** Short, jargon-free label for the class of config: shown as a badge. */
    val kind: ServerKind
        get() = when {
            security == "reality" -> ServerKind.Direct
            transport in CDN_TRANSPORTS && security == "tls" -> ServerKind.Cdn
            else -> ServerKind.Other
        }

    companion object {
        const val SOURCE_USER = "user"
        const val SOURCE_SUB_PREFIX = "sub:"
        const val SOURCE_FEED_PREFIX = "feed:"
        private val CDN_TRANSPORTS = setOf("ws", "grpc", "xhttp", "httpupgrade")

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
        )
    }
}

enum class ServerKind { Direct, Cdn, Other }

/** What the user asked to connect to. */
sealed interface ConnectTarget {
    /** Discover and pick the best config automatically. */
    data object Fastest : ConnectTarget
    data class Country(val code: String) : ConnectTarget
    data class Specific(val key: String) : ConnectTarget

    fun encode(): String = when (this) {
        Fastest -> "fastest"
        is Country -> "country:$code"
        is Specific -> "server:$key"
    }

    companion object {
        fun decode(value: String?): ConnectTarget = when {
            value == null || value == "fastest" -> Fastest
            value.startsWith("country:") -> Country(value.removePrefix("country:"))
            value.startsWith("server:") -> Specific(value.removePrefix("server:"))
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
