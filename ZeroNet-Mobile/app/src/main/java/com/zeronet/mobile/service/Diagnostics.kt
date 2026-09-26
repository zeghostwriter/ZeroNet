package com.zeronet.mobile.service

import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.DiagCheck
import java.io.EOFException
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The network half of the connection self-test: what the phone's own network
 * does to plain traffic, outside the tunnel. Each probe is blocking; the
 * engine runs them on the IO dispatcher. The :vpn process is excluded from
 * its own VPN, so these always see the raw network, connected or not.
 *
 * Nothing here sends data beyond a DNS query, one HTTP request to Google's
 * connectivity check and two TLS ClientHellos; no certificate is trusted
 * for anything, as no application data follows the handshakes.
 */
object Diagnostics {
    const val NETWORK = "network"
    const val INTERNET = "internet"
    const val DNS = "dns"
    const val TLS = "tls"
    const val TUNNEL = "tunnel"
    const val FAMILY_PREFIX = "family_"

    private const val PROBE = "http://www.gstatic.com/generate_204"
    private const val TIMEOUT_MS = 6_000

    /** Sites filtered in Iran whose DNS answers are commonly poisoned. */
    private val FILTERED_NAMES = listOf("www.youtube.com", "twitter.com", "www.instagram.com", "telegram.org")
    /** A name that is not filtered, to tell "DNS is poisoned" from "DNS does not work". */
    private const val CONTROL_NAME = "www.google.com"

    /**
     * A Cloudflare anycast address: any of them answers a ClientHello for any
     * name, so the two handshakes below differ only in the SNI they carry.
     */
    private const val TLS_ADDRESS = "104.16.123.96"
    private const val CONTROL_SNI = "www.cloudflare.com"
    private const val FILTERED_SNI = "www.youtube.com"

    /** Plain HTTP out of the phone's network: works, is redirected to a block page, or goes nowhere. */
    fun internet(): DiagCheck = runCatching {
        val conn = URL(PROBE).openConnection(Proxy.NO_PROXY) as HttpURLConnection
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.instanceFollowRedirects = false
        try {
            when (val code = conn.responseCode) {
                204 -> DiagCheck(INTERNET, CheckStatus.Ok, "HTTP 204")
                in 300..399 -> DiagCheck(INTERNET, CheckStatus.Warn, "redirected to ${conn.getHeaderField("Location").orEmpty().take(80)}")
                else -> DiagCheck(INTERNET, CheckStatus.Warn, "HTTP $code (a captive portal or a filter answered)")
            }
        } finally {
            conn.disconnect()
        }
    }.getOrElse { DiagCheck(INTERNET, CheckStatus.Bad, errorText(it)) }

    /** Whether the network's resolver lies about filtered names. */
    fun dns(): DiagCheck {
        val control = resolve(CONTROL_NAME)
        if (control.isFailure) {
            return DiagCheck(DNS, CheckStatus.Bad, "$CONTROL_NAME: ${errorText(control.exceptionOrNull())}")
        }
        val poisoned = ArrayList<String>()
        val failed = ArrayList<String>()
        for (name in FILTERED_NAMES) {
            val answer = resolve(name)
            val addresses = answer.getOrNull()
            when {
                addresses == null -> failed += name
                addresses.any(::isBogus) -> poisoned += "$name → ${addresses.first().hostAddress}"
            }
        }
        return when {
            poisoned.isNotEmpty() -> DiagCheck(DNS, CheckStatus.Bad, poisoned.joinToString("; "))
            failed.isNotEmpty() -> DiagCheck(DNS, CheckStatus.Warn, "no answer for ${failed.joinToString()}")
            else -> DiagCheck(DNS, CheckStatus.Ok, "${FILTERED_NAMES.size} filtered names resolve to real addresses")
        }
    }

    /**
     * Deep packet inspection of the TLS server name: the same address is
     * greeted twice, once with an innocuous name and once with a filtered
     * one. A reset or silence only for the filtered name is the DPI box.
     */
    fun tls(): DiagCheck {
        val control = handshake(CONTROL_SNI)
        val filtered = handshake(FILTERED_SNI)
        return when {
            !control.first -> DiagCheck(TLS, CheckStatus.Bad, "TLS to Cloudflare fails even for $CONTROL_SNI: ${control.second}")
            !filtered.first -> DiagCheck(TLS, CheckStatus.Bad, "SNI filtering: $FILTERED_SNI ${filtered.second}")
            else -> DiagCheck(TLS, CheckStatus.Ok, "no SNI filtering seen")
        }
    }

    /** Plain HTTP through the local proxy into the running tunnel. */
    fun tunnel(httpPort: Int): DiagCheck = runCatching {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort))
        val started = System.nanoTime()
        val conn = URL(PROBE).openConnection(proxy) as HttpURLConnection
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.instanceFollowRedirects = false
        try {
            val code = conn.responseCode
            val ms = (System.nanoTime() - started) / 1_000_000
            if (code == 204) DiagCheck(TUNNEL, CheckStatus.Ok, "HTTP 204 in $ms ms")
            else DiagCheck(TUNNEL, CheckStatus.Warn, "HTTP $code in $ms ms")
        } finally {
            conn.disconnect()
        }
    }.getOrElse { DiagCheck(TUNNEL, CheckStatus.Bad, errorText(it)) }

    // ------------------------------------------------------------ helpers

    private fun resolve(name: String): Result<List<InetAddress>> = runCatching { InetAddress.getAllByName(name).toList() }

    /** Answers a poisoning resolver gives: Iran's block-page range, private, loopback, unspecified. */
    fun isBogus(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) return true
        return when (address) {
            is Inet4Address -> {
                val b = address.address
                val first = b[0].toInt() and 0xff
                val second = b[1].toInt() and 0xff
                // 10.10.34.0/24 (the block page) is inside 10/8, already caught
                // as site-local; 100.64/10 (carrier NAT) and 198.18/15 are not
                // real destinations either.
                (first == 100 && second in 64..127) || (first == 198 && second in 18..19) || first == 0
            }
            is Inet6Address -> false
            else -> false
        }
    }

    /** (reached the server, what happened). A certificate or alert error still means the server answered. */
    private fun handshake(sni: String): Pair<Boolean, String> {
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(TLS_ADDRESS, 443), TIMEOUT_MS)
            socket.soTimeout = TIMEOUT_MS
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(socket, sni, 443, true) as SSLSocket
            ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
            ssl.use { it.startHandshake() }
            true to "handshake completed"
        } catch (e: SocketTimeoutException) {
            false to "timed out (no answer)"
        } catch (e: SSLException) {
            // Reset or closed mid-handshake is interference; an alert or a
            // certificate the phone does not like means the server answered.
            val text = e.message.orEmpty().lowercase()
            if ("reset" in text || "closed" in text || "eof" in text || e.cause is SocketException || e.cause is EOFException) {
                false to "connection reset during the handshake"
            } else {
                true to "server answered (${e.javaClass.simpleName})"
            }
        } catch (e: SocketException) {
            false to "connection reset (${e.message.orEmpty().take(60)})"
        } catch (e: Exception) {
            false to errorText(e)
        } finally {
            runCatching { socket.close() }
        }
    }

    fun errorText(error: Throwable?): String = when (error) {
        null -> "unknown error"
        is SocketTimeoutException -> "timed out"
        is java.net.UnknownHostException -> "name not resolved"
        is java.net.ConnectException -> "connection refused or unreachable"
        else -> "${error.javaClass.simpleName}: ${error.message.orEmpty().take(80)}"
    }
}
