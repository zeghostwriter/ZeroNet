package com.zeronet.mobile.ui.effects

import kotlin.math.abs
import kotlin.math.sin

/**
 * What the connect banner says and how it moves. Everything here is a pure
 * function of its inputs, so the drawing code stays small and the behaviour is
 * checked in plain unit tests.
 */
object ProtocolBannerFx {
    /** Shown when the protocol is missing or is one this app has no name for. */
    const val UNKNOWN = "CUSTOM?"

    /** Protocols whose carrier is part of their name: no transport or security is added to them. */
    private val SELF_CONTAINED = setOf("hysteria2", "hy2", "tuic", "juicity", "anytls", "zerov1", "tide", "masterdns", "amnezia-wg", "wireguard", "socks", "tor", "freedom")

    private fun protocolName(protocol: String): String? = when (protocol.trim().lowercase()) {
        "vless" -> "VLESS"
        "vmess" -> "VMESS"
        "trojan" -> "TROJAN"
        "ss", "shadowsocks" -> "SHADOWSOCKS"
        // The 2 is the Persian digit (U+06F2), by choice.
        "hysteria2", "hy2" -> "HYSTERIA \u06F2"
        "tuic" -> "TUIC"
        "juicity" -> "JUICITY"
        "anytls" -> "ANYTLS"
        "zerov1", "tide" -> "ZEROV1"
        "masterdns" -> "MASTERDNSVPN"
        "amnezia-wg", "wireguard" -> "WIREGUARD"
        "socks" -> "SOCKS5"
        "tor" -> "TOR"
        "freedom" -> "SERVERLESS"
        else -> null
    }

    private fun transportName(transport: String): String? = when (transport.trim().lowercase()) {
        "ws", "websocket" -> "WS"
        "grpc" -> "GRPC"
        "xhttp", "splithttp" -> "XHTTP"
        "httpupgrade" -> "HTTPUPGRADE"
        else -> null // plain TCP says nothing; QUIC is part of the protocol's name
    }

    private fun securityName(security: String): String? = when (security.trim().lowercase()) {
        "reality" -> "REALITY"
        "tls" -> "TLS"
        "shadowtls" -> "SHADOWTLS"
        else -> null
    }

    /**
     * The words on the banner: the protocol, then the transport when it is not
     * plain TCP, then the security layer: `VLESS + REALITY`,
     * `VLESS + XHTTP + REALITY`, `TROJAN + TLS`, `HYSTERIA 2`. A WARP account
     * is a WireGuard tunnel and says so. [UNKNOWN] when the protocol is not
     * recognised.
     */
    fun label(protocol: String, transport: String, security: String, warp: Boolean = false): String {
        val name = protocolName(protocol) ?: return UNKNOWN
        val parts = ArrayList<String>(3)
        parts += if (warp) "WARP + $name" else name
        if (protocol.trim().lowercase() !in SELF_CONTAINED) {
            transportName(transport)?.let { parts += it }
            securityName(security)?.let { parts += it }
        }
        return parts.joinToString(" + ")
    }

    // ----------------------------------------------------------------- runs

    /**
     * One stretch of the banner with its own treatment. [color] is an opaque
     * ARGB, or null for the protocol's own colour. [ink] marks letters drawn as
     * a black fill with a thin outline in the protocol's colour, so black stays
     * readable on a dark screen.
     */
    data class Run(val start: Int, val end: Int, val color: Long?, val bold: Boolean, val ink: Boolean = false)

    const val RED = 0xFFFF2B3DL
    const val BLACK = 0xFF000000L

    /**
     * The runs of a banner, covering every character in order, with no gaps.
     * Almost every banner is one bold run in the protocol's colour; two are
     * dressed up: the J of TROJAN is red, and MASTERDNSVPN reads MASTER in bold,
     * DNS in red and not bold, and VPN in black. On a pure-black (AMOLED) screen
     * that black is true black and bold; elsewhere it is plain black, not bold.
     */
    fun runs(label: String, protocol: String, amoled: Boolean): List<Run> {
        val special = ArrayList<Run>(2)
        when (protocol.trim().lowercase()) {
            "trojan" -> if (label.startsWith("TROJAN")) special += Run(3, 4, RED, true)
            "masterdns" -> if (label == "MASTERDNSVPN") {
                special += Run(6, 9, RED, false)
                special += Run(9, 12, BLACK, bold = amoled, ink = true)
            }
        }
        val all = ArrayList<Run>(special.size * 2 + 1)
        var at = 0
        for (run in special) {
            if (run.start > at) all += Run(at, run.start, null, true)
            all += run
            at = run.end
        }
        if (at < label.length) all += Run(at, label.length, null, true)
        return all
    }

    // ----------------------------------------------------------------- look

    /**
     * How one banner is drawn: a single colour (opaque ARGB), one of the
     * device's built-in font families and whether it leans. Every protocol has
     * its own, so the line tells them apart before it is read.
     */
    data class Look(val color: Long, val font: String, val italic: Boolean, val tracking: Float)

    private val LOOKS = mapOf(
        "vless" to Look(0xFF19E6FF, "sans-serif-condensed", true, 2.0f),
        "vmess" to Look(0xFFFF8A1F, "serif-monospace", false, 1.5f),
        "trojan" to Look(0xFFFF4F9A, "serif", true, 1.5f),
        "shadowsocks" to Look(0xFF5CFF5C, "monospace", false, 1.0f),
        "hysteria2" to Look(0xFFA56BFF, "sans-serif-black", true, 1.5f),
        "tuic" to Look(0xFFFFE53D, "casual", false, 2.5f),
        "juicity" to Look(0xFFFF5C5C, "cursive", true, 2.0f),
        "anytls" to Look(0xFF1FFFC8, "sans-serif-medium", false, 5.0f),
        "zerov1" to Look(0xFFFFB300, "sans-serif-black", false, 3.0f),
        "masterdns" to Look(0xFF4D8DFF, "monospace", true, 0.5f),
        "wireguard" to Look(0xFFFF3B5C, "sans-serif-condensed", false, 3.0f),
        "socks" to Look(0xFFC9D6FF, "serif-monospace", true, 1.5f),
        "tor" to Look(0xFFC04DFF, "serif", false, 4.0f),
        "freedom" to Look(0xFFB8FF3D, "sans-serif-light", false, 3.5f),
    )

    /** The look of a config nobody has a name for. */
    val CUSTOM_LOOK = Look(0xFFF2F2F2, "cursive", true, 3.0f)

    /** The look for a protocol as the core spells it; [CUSTOM_LOOK] when it is not one this app names. */
    fun look(protocol: String): Look {
        val key = when (protocol.trim().lowercase()) {
            "ss" -> "shadowsocks"
            "hy2" -> "hysteria2"
            "tide" -> "zerov1"
            "amnezia-wg" -> "wireguard"
            else -> protocol.trim().lowercase()
        }
        return LOOKS[key] ?: CUSTOM_LOOK
    }

    /** Every look in use, for a check that no two protocols share a colour. */
    internal fun allLooks(): Map<String, Look> = LOOKS

    // --------------------------------------------------------------- motion

    /** How long the letters churn before they settle, in milliseconds. */
    const val REVEAL_MS = 1100L

    private const val STEP_MS = 55L

    /**
     * The text [elapsedMs] after the banner appeared: letters settle left to
     * right on the real characters, the rest churn through hex digits and marks
     * (the same tables as the key-decryption effect). Spaces and plus signs
     * never churn, so the shape of the line is readable from the first frame.
     */
    fun scramble(template: String, elapsedMs: Long, seed: ULong): String {
        if (elapsedMs >= REVEAL_MS) return template
        val letters = template.count { it.isLetterOrDigit() || it == '?' }
        val settled = (elapsedMs * (letters + 1) / REVEAL_MS).toInt()
        var seen = 0
        val step = (elapsedMs / STEP_MS).toULong()
        val sb = StringBuilder(template.length)
        for ((index, ch) in template.withIndex()) {
            if (!(ch.isLetterOrDigit() || ch == '?')) {
                sb.append(ch)
                continue
            }
            if (seen < settled) {
                sb.append(ch)
            } else {
                val h = KeyFx.mix(seed, index.toULong(), step)
                val pick = h shr 8
                sb.append(
                    if ((h shr 48) % 100UL < 62UL) KeyFx.HEX[(pick % KeyFx.HEX.length.toULong()).toInt()]
                    else KeyFx.MARKS[(pick % KeyFx.MARKS.length.toULong()).toInt()],
                )
            }
            seen += 1
        }
        return sb.toString()
    }

    /** A stable seed for a label, so the same banner churns the same way. */
    fun seed(text: String): ULong = text.fold(0xCBF29CE484222325uL) { h, c -> (h xor c.code.toULong()) * 0x100000001B3uL }

    /**
     * How far apart the two ghost copies of the text sit, in dp-like units
     * (1.0 is a wide split). Wide while the letters churn, then a thin steady
     * echo with short glitch spikes now and then.
     */
    fun split(elapsedMs: Long, seed: ULong): Float {
        val reveal = (1f - elapsedMs.coerceAtLeast(0) / (REVEAL_MS * 1.6f)).coerceIn(0f, 1f)
        // A spike every 2.4 s that lasts a few frames, placed by the seed so two banners do not glitch together.
        val period = 2400L
        val into = (elapsedMs + (seed % period.toULong()).toLong()) % period
        val spike = if (into < 140) 1f - into / 140f else 0f
        val breathing = 0.5f + 0.5f * sin(elapsedMs / 700f)
        return (0.18f + 0.1f * breathing + 0.55f * spike + 0.9f * reveal).coerceIn(0f, 1.5f)
    }

    /** Where the bright glint is, as a fraction of the width (past 1 means it is between passes). */
    fun glint(elapsedMs: Long): Float {
        val period = 3200L
        val t = (elapsedMs % period) / 1100f
        return if (t > 1.3f) 2f else -0.3f + t * 1.3f
    }

    /** How opaque the banner is: it fades in over the first 350 ms. */
    fun alpha(elapsedMs: Long): Float = (elapsedMs / 350f).coerceIn(0f, 1f)

    /** The scale it lands from: slightly large, settling to 1. */
    fun scale(elapsedMs: Long): Float {
        val t = (elapsedMs / 450f).coerceIn(0f, 1f)
        return 1f + 0.18f * (1f - t) * (1f - t)
    }

    /** How much the split differs between two instants: handy to assert that it moves. */
    internal fun movement(a: Long, b: Long, seed: ULong): Float = abs(split(a, seed) - split(b, seed))
}
