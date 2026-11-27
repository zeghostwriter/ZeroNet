package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.effects.ProtocolBannerFx
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolBannerFxTest {
    private fun label(protocol: String, transport: String = "tcp", security: String = "none", warp: Boolean = false) =
        ProtocolBannerFx.label(protocol, transport, security, warp)

    @Test fun `the protocol and its security read as one line`() {
        assertEquals("VLESS + REALITY", label("vless", "tcp", "reality"))
        assertEquals("VLESS + XHTTP + REALITY", label("vless", "xhttp", "reality"))
        assertEquals("VLESS + WS + TLS", label("vless", "ws", "tls"))
        assertEquals("VLESS + GRPC", label("vless", "grpc", "none"))
        assertEquals("TROJAN + TLS", label("trojan", "tcp", "tls"))
        assertEquals("VMESS", label("vmess"))
        assertEquals("SHADOWSOCKS", label("ss"))
    }

    @Test fun `a protocol that carries itself gets nothing added`() {
        assertEquals("HYSTERIA \u06F2", label("hysteria2", "quic", "tls"))
        assertEquals("TUIC", label("tuic", "quic", "tls"))
        // A direct:// profile has no server, so the banner says Serverless, not how it hides.
        assertEquals("SERVERLESS", label("freedom", "tcp", "none"))
        assertEquals("ANYTLS", label("anytls", "tcp", "tls"))
        assertEquals("MASTERDNSVPN", label("masterdns", "tcp", "none"))
        assertEquals("WIREGUARD", label("amnezia-wg"))
    }

    @Test fun `the 2 of hysteria is the persian digit`() {
        val text = label("hysteria2", "quic", "tls")
        assertTrue(text.endsWith("\u06F2"))
        assertFalse(text.contains('2'))
        // It still churns and settles like every other character.
        val seed = ProtocolBannerFx.seed(text)
        assertEquals(text, ProtocolBannerFx.scramble(text, ProtocolBannerFx.REVEAL_MS, seed))
        assertEquals(text.length, ProtocolBannerFx.scramble(text, 100, seed).length)
    }

    private fun covers(runs: List<ProtocolBannerFx.Run>, length: Int) {
        assertEquals(0, runs.first().start)
        assertEquals(length, runs.last().end)
        runs.zipWithNext().forEach { (a, b) -> assertEquals("no gap or overlap", a.end, b.start) }
    }

    @Test fun `most banners are one bold run in the protocols own colour`() {
        val text = label("vless", "tcp", "reality")
        val runs = ProtocolBannerFx.runs(text, "vless", amoled = false)
        assertEquals(1, runs.size)
        assertEquals(null, runs[0].color)
        assertTrue(runs[0].bold)
        covers(runs, text.length)
    }

    @Test fun `the J in trojan is red and the rest is not`() {
        val text = label("trojan", "tcp", "tls")
        assertEquals("TROJAN + TLS", text)
        val runs = ProtocolBannerFx.runs(text, "trojan", amoled = false)
        covers(runs, text.length)
        val red = runs.single { it.color == ProtocolBannerFx.RED }
        assertEquals('J', text[red.start])
        assertEquals(1, red.end - red.start)
        assertTrue(red.bold)
        assertTrue(runs.filter { it !== red }.all { it.color == null })
    }

    @Test fun `masterdnsvpn is master bold, dns red and light, vpn black`() {
        val text = label("masterdns", "tcp", "none")
        assertEquals("MASTERDNSVPN", text)
        val runs = ProtocolBannerFx.runs(text, "masterdns", amoled = false)
        covers(runs, text.length)
        val (master, dns, vpn) = runs
        assertEquals("MASTER", text.substring(master.start, master.end))
        assertTrue(master.bold); assertEquals(null, master.color)
        assertEquals("DNS", text.substring(dns.start, dns.end))
        assertFalse(dns.bold); assertEquals(ProtocolBannerFx.RED, dns.color)
        assertEquals("VPN", text.substring(vpn.start, vpn.end))
        assertEquals(ProtocolBannerFx.BLACK, vpn.color)
        assertFalse("not bold on an ordinary screen", vpn.bold)
        assertTrue("outlined so it stays readable", vpn.ink)
    }

    @Test fun `on a pure black screen the vpn letters are bold true black`() {
        val vpn = ProtocolBannerFx.runs("MASTERDNSVPN", "masterdns", amoled = true).last()
        assertEquals(ProtocolBannerFx.BLACK, vpn.color)
        assertTrue(vpn.bold)
    }

    @Test fun `a changed label gets no special dress`() {
        // A different text for the same protocol (not the expected one) stays plain.
        assertEquals(1, ProtocolBannerFx.runs("CUSTOM?", "masterdns", amoled = false).size)
        assertEquals(1, ProtocolBannerFx.runs("WARP + WIREGUARD", "amnezia-wg", amoled = false).size)
    }

    @Test fun `a WARP account says so`() {
        assertEquals("WARP + WIREGUARD", label("amnezia-wg", warp = true))
    }

    @Test fun `a missing or unknown protocol is a custom config`() {
        assertEquals("CUSTOM?", label(""))
        assertEquals("CUSTOM?", label("   "))
        assertEquals("CUSTOM?", label("somethingnew", "ws", "tls"))
    }

    @Test fun `the line never says it is connected`() {
        listOf("vless", "trojan", "hysteria2", "", "x").forEach {
            assertFalse(label(it, "ws", "tls").contains("CONNECT", ignoreCase = true))
        }
    }

    @Test fun `the letters settle left to right and the shape of the line is kept from the first frame`() {
        val text = "VLESS + XHTTP + REALITY"
        val seed = ProtocolBannerFx.seed(text)
        val first = ProtocolBannerFx.scramble(text, 0, seed)
        assertEquals(text.length, first.length)
        text.forEachIndexed { i, ch -> if (ch == ' ' || ch == '+') assertEquals(ch, first[i]) }
        assertEquals(text, ProtocolBannerFx.scramble(text, ProtocolBannerFx.REVEAL_MS, seed))
        assertEquals(text, ProtocolBannerFx.scramble(text, ProtocolBannerFx.REVEAL_MS * 3, seed))
        // Halfway, a prefix is real and the end is still churning.
        val half = ProtocolBannerFx.scramble(text, ProtocolBannerFx.REVEAL_MS / 2, seed)
        assertEquals(text.take(4), half.take(4))
        assertNotEquals(text.takeLast(4), half.takeLast(4))
    }

    @Test fun `the same banner churns the same way and different ones do not`() {
        val a = ProtocolBannerFx.seed("VLESS + REALITY")
        assertEquals(ProtocolBannerFx.scramble("VLESS + REALITY", 200, a), ProtocolBannerFx.scramble("VLESS + REALITY", 200, a))
        assertNotEquals(a, ProtocolBannerFx.seed("TROJAN + TLS"))
    }

    @Test fun `every protocol has its own colour and the unknown one has a look too`() {
        val looks = ProtocolBannerFx.allLooks()
        assertEquals("no two protocols may share a colour", looks.size, looks.values.map { it.color }.toSet().size)
        assertTrue("fonts vary", looks.values.map { it.font }.toSet().size >= 6)
        // Every look is a solid colour: a protocol is one colour, never a gradient.
        assertTrue(looks.values.all { (it.color ushr 24) == 0xFFL })
        assertEquals(ProtocolBannerFx.look("vless"), ProtocolBannerFx.look(" VLESS "))
        assertEquals(ProtocolBannerFx.look("ss"), ProtocolBannerFx.look("shadowsocks"))
        assertEquals(ProtocolBannerFx.look("amnezia-wg"), ProtocolBannerFx.look("wireguard"))
        assertEquals(ProtocolBannerFx.CUSTOM_LOOK, ProtocolBannerFx.look(""))
        assertEquals(ProtocolBannerFx.CUSTOM_LOOK, ProtocolBannerFx.look("somethingnew"))
        assertTrue(looks.values.none { it.color == ProtocolBannerFx.CUSTOM_LOOK.color })
    }

    @Test fun `the colour split starts wide, settles, and keeps moving a little`() {
        val seed = ProtocolBannerFx.seed("VLESS + REALITY")
        assertTrue(ProtocolBannerFx.split(0, seed) > ProtocolBannerFx.split(4_000, seed) + 0.4f)
        (0L..30_000L step 37L).forEach { t ->
            assertTrue(ProtocolBannerFx.split(t, seed) in 0f..1.5f)
        }
        assertTrue(ProtocolBannerFx.movement(5_000, 5_700, seed) > 0f)
    }

    @Test fun `it fades and lands in the first half second only`() {
        assertEquals(0f, ProtocolBannerFx.alpha(0), 0f)
        assertEquals(1f, ProtocolBannerFx.alpha(400), 0f)
        assertTrue(ProtocolBannerFx.scale(0) > 1f)
        assertEquals(1f, ProtocolBannerFx.scale(500), 0f)
    }

    @Test fun `the glint crosses the line then rests between passes`() {
        assertTrue(ProtocolBannerFx.glint(0) < 0.1f)
        assertTrue(ProtocolBannerFx.glint(600) in 0.1f..1.0f)
        assertEquals(2f, ProtocolBannerFx.glint(2_000), 0f)
    }
}
