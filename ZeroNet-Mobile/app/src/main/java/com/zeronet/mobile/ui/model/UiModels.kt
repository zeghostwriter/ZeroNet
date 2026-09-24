package com.zeronet.mobile.ui.model

import android.content.Context
import androidx.compose.runtime.Immutable
import com.zeronet.mobile.R
import com.zeronet.mobile.data.Sources
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.ServerKind
import com.zeronet.mobile.ui.util.Countries
import java.util.Locale

/** Servers of one country, for the Countries list and the server picker. */
@Immutable
data class CountryGroup(
    val code: String,
    val servers: List<Server>,
) {
    val count: Int get() = servers.size
    val bestDelay: Int = servers.filter { it.delayMs >= 0 }.minOfOrNull { it.delayMs } ?: -1
    val working: Int = servers.count { it.delayMs >= 0 }
}

/** Group servers by country: countries with a working server first (by best ping), unknown last. */
fun groupByCountry(servers: List<Server>): List<CountryGroup> =
    servers.groupBy { it.country.ifBlank { "" } }
        .map { (code, list) -> CountryGroup(code, list.sortedWith(compareBy<Server> { if (it.delayMs < 0) 1 else 0 }.thenBy { it.delayMs })) }
        .sortedWith(
            compareBy<CountryGroup> { if (it.code.isEmpty()) 2 else if (it.bestDelay < 0) 1 else 0 }
                .thenBy { if (it.bestDelay < 0) Int.MAX_VALUE else it.bestDelay }
                .thenByDescending { it.count },
        )

fun countryLabel(context: Context, code: String, locale: Locale): String =
    Countries.name(code, locale).ifBlank { context.getString(R.string.country_unknown) }

/** The name shown for a server: its country when the remark is just an address or noise. */
fun serverTitle(context: Context, server: Server, locale: Locale): String {
    val name = server.name.trim()
    val country = Countries.name(server.country, locale)
    return when {
        name.isBlank() || name == server.host -> country.ifBlank { server.host }
        else -> name
    }
}

fun kindLabel(context: Context, kind: ServerKind): String = context.getString(
    when (kind) {
        ServerKind.Direct -> R.string.kind_direct
        ServerKind.Cdn -> R.string.kind_cdn
        ServerKind.Other -> R.string.kind_other
    },
)

/** Protocol names appear only in the detail sheet; these are their conventional spellings. */
fun protocolLabel(p: String): String = when (p.lowercase(Locale.ROOT)) {
    "vless" -> "VLESS"
    "vmess" -> "VMess"
    "trojan" -> "Trojan"
    "ss", "shadowsocks" -> "Shadowsocks"
    "hysteria2", "hy2" -> "Hysteria 2"
    "tuic" -> "TUIC"
    "anytls" -> "AnyTLS"
    "" -> "—"
    else -> p
}

fun transportLabel(t: String): String = when (t.lowercase(Locale.ROOT)) {
    "tcp", "raw" -> "TCP"
    "ws" -> "WebSocket"
    "grpc" -> "gRPC"
    "xhttp" -> "XHTTP"
    "httpupgrade" -> "HTTP Upgrade"
    "quic" -> "QUIC"
    "kcp", "mkcp" -> "mKCP"
    "h2", "http" -> "HTTP/2"
    "" -> "—"
    else -> t
}

fun securityLabel(s: String): String = when (s.lowercase(Locale.ROOT)) {
    "reality" -> "REALITY"
    "tls" -> "TLS"
    "none", "" -> "—"
    else -> s.uppercase(Locale.ROOT)
}

/** Where a server came from, in words. */
fun sourceLabel(context: Context, source: String, subscriptions: List<Subscription>): String = when {
    source == Server.SOURCE_USER -> context.getString(R.string.source_user)
    source.startsWith(Server.SOURCE_SUB_PREFIX) -> {
        val id = source.removePrefix(Server.SOURCE_SUB_PREFIX)
        subscriptions.firstOrNull { it.id == id }?.name?.ifBlank { null } ?: context.getString(R.string.source_subscription)
    }
    source.startsWith(Server.SOURCE_FEED_PREFIX) -> {
        val id = source.removePrefix(Server.SOURCE_FEED_PREFIX)
        Sources.builtIn.firstOrNull { it.id == id }?.let { context.getString(R.string.source_feed, it.name) }
            ?: context.getString(R.string.source_public)
    }
    source == "history" -> context.getString(R.string.source_public)
    else -> context.getString(R.string.source_public)
}

fun failReasonText(context: Context, reason: FailReason): String = context.getString(
    when (reason) {
        FailReason.NoWorkingServer -> R.string.fail_no_server
        FailReason.NoNetwork -> R.string.fail_no_network
        FailReason.VpnPermission -> R.string.fail_vpn_permission
        FailReason.VpnRevoked -> R.string.fail_vpn_revoked
        FailReason.CoreError -> R.string.fail_core
        FailReason.ServerUnavailable -> R.string.fail_server_unavailable
    },
)

val ConnState.isBusy: Boolean
    get() = this is ConnState.Searching || this is ConnState.Connecting || this is ConnState.Reconnecting || this is ConnState.Disconnecting
