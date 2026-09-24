package com.zeronet.mobile.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import java.security.MessageDigest

/**
 * A stable, privacy-preserving name for "the network I'm on right now".
 *
 * Which configs survive filtering differs by ISP (MCI vs Irancell vs home
 * fibre), so history is kept per network. Reading a Wi-Fi SSID needs the
 * location permission, which a VPN has no business asking for; instead the
 * identity is a hash of what is visible without permissions: the transport,
 * the carrier name for cellular, and the default gateway / DNS servers /
 * search domains for everything else. Only the hash is stored.
 */
object NetworkIdentity {
    fun current(context: Context): String? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null
        val raw = StringBuilder()
        when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                raw.append("cell|")
                val tm = context.getSystemService(TelephonyManager::class.java)
                raw.append(tm?.networkOperator.orEmpty()).append('|').append(tm?.networkOperatorName.orEmpty())
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> raw.append("wifi|")
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> raw.append("eth|")
            else -> raw.append("other|")
        }
        cm.getLinkProperties(network)?.let { lp ->
            lp.routes.filter { it.isDefaultRoute }.mapNotNull { it.gateway?.hostAddress }.sorted().forEach { raw.append(it).append(',') }
            raw.append('|')
            lp.dnsServers.mapNotNull { it.hostAddress }.sorted().forEach { raw.append(it).append(',') }
            raw.append('|').append(lp.domains.orEmpty())
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toString().toByteArray())
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    /** Human label for the UI ("Irancell", "Wi-Fi"), never persisted. */
    fun label(context: Context): String {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return ""
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) } ?: return ""
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                context.getSystemService(TelephonyManager::class.java)?.networkOperatorName.orEmpty().ifBlank { "Mobile" }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> ""
        }
    }
}
