package com.zeronet.mobile.ui

import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.TrafficStats
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.sin

/** Deterministic fake model data for the screenshot tests. */
object Fixtures {
    /** A fixed "now" so relative times and the session timer never change between runs. */
    const val NOW = 1_790_000_000_000L

    private fun server(
        key: String,
        name: String,
        country: String,
        delay: Int,
        protocol: String = "vless",
        transport: String = "ws",
        security: String = "tls",
        source: String = "feed:limilco",
        favorite: Boolean = false,
        alive: Int = 0,
        fail: Int = 0,
    ) = Server(
        key = key,
        link = "$protocol://2f6a1c3e-7b9d-4e21-a8f0-5c3d2b1e9f77@$key.example.net:443?security=$security&type=$transport#$name",
        name = name,
        protocol = protocol,
        transport = transport,
        security = security,
        host = "$key.example.net",
        port = 443,
        country = country,
        source = source,
        favorite = favorite,
        delayMs = delay,
        lastTestedAt = if (delay >= 0) NOW - 4 * 60_000 else 0,
        aliveCount = alive,
        failCount = fail,
    )

    val germany = server("de1", "de1.example.net", "DE", 142, security = "reality", transport = "tcp", favorite = true, alive = 18, fail = 2)

    val servers: List<Server> = listOf(
        germany,
        server("nl1", "nl1.example.net", "NL", 168, alive = 9, fail = 1),
        server("fi1", "Helsinki fast", "FI", 205, transport = "grpc"),
        server("de2", "de2.example.net", "DE", 231, transport = "xhttp"),
        server("tr1", "tr1.example.net", "TR", 96, protocol = "trojan", security = "tls", transport = "tcp"),
        server("ae1", "ae1.example.net", "AE", 388, protocol = "ss", security = "", transport = "tcp"),
        server("us1", "us1.example.net", "US", 612, transport = "ws"),
        server("fr1", "fr1.example.net", "FR", 940, protocol = "vmess"),
        server("nl2", "nl2.example.net", "NL", -1),
        server("se1", "se1.example.net", "SE", -1),
        server("my1", "My home server", "DE", 187, source = Server.SOURCE_USER, favorite = true, alive = 40, fail = 3),
        server("my2", "Work VPS", "FI", -1, protocol = "hysteria2", transport = "quic", security = "tls", source = "sub:s1"),
        server("xx1", "203.0.113.7", "", 455),
    )

    val subscriptions = listOf(
        Subscription(id = "s1", name = "My provider", url = "https://sub.example.com/abc", enabled = true, updatedAt = NOW - 3 * 3_600_000, count = 24),
    )

    /** 60 s of plausible throughput: a download burst with some upload chatter. */
    val stats: TrafficStats = run {
        val down = List(60) { i ->
            val base = 1_450_000.0 + 900_000.0 * sin(i / 60.0 * 2 * PI * 1.6)
            val burst = if (i in 34..44) 1_800_000.0 * sin((i - 34) / 10.0 * PI) else 0.0
            (base + burst + 180_000.0 * abs(sin(i * 1.7))).toLong().coerceAtLeast(40_000)
        }
        val up = List(60) { i -> (120_000.0 + 90_000.0 * abs(sin(i * 0.9)) + 60_000.0 * sin(i / 8.0)).toLong().coerceAtLeast(8_000) }
        TrafficStats(
            upRate = up.last(),
            downRate = 2_620_000,
            upTotal = 48_300_000,
            downTotal = 1_240_000_000,
            downHistory = down,
            upHistory = up,
        )
    }

    val scanRunning = ScanState(
        running = true,
        scanned = 1_240,
        responsive = 38,
        total = 2_000,
        results = listOf(
            ScanResult("104.16.132.229", 443, 118),
            ScanResult("172.67.182.11", 443, 131),
            ScanResult("104.21.48.90", 2053, 146),
            ScanResult("188.114.97.3", 443, 163),
            ScanResult("162.159.140.24", 8443, 190),
            ScanResult("104.17.3.81", 443, 214),
            ScanResult("172.64.155.70", 443, 267),
            ScanResult("104.26.9.144", 2096, 342),
        ),
    )
}
