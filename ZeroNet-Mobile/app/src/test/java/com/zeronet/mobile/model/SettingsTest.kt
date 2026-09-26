package com.zeronet.mobile.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class SettingsTest {

    @Test
    fun `every field survives a JSON round trip`() {
        val original = Settings(
            mode = ConnectionMode.Proxy,
            autoConnect = AutoConnect.OnBoot,
            autoSwitch = false,
            ipv6 = true,
            mtu = 1400,
            lastTarget = ConnectTarget.Country("DE").encode(),
            disabledSources = setOf("delta", "mheidari"),
            preferredCountries = listOf("NL", "DE"),
            autoRefresh = false,
            iranDirect = false,
            bypassLan = false,
            appFilter = AppFilterMode.OnlySelected,
            filteredApps = setOf("org.telegram.messenger"),
            lanShare = true,
            socksPort = 20808,
            httpPort = 20809,
            lanUser = "u",
            lanPass = "p@ss",
            evasion = EvasionLevel.Strong,
            blockQuic = false,
            remoteDns = RemoteDns.Quad9,
            antiSanctionDns = AntiSanctionDns.Electro,
            customAntiSanction = "10.202.10.10",
            fragmentPackets = "1-1",
            fakeDns = false,
            blockAds = false,
            themeMode = ThemeMode.Dark,
            palette = Palette.Arctic,
            dynamicColor = true,
            amoled = true,
            language = AppLanguage.Persian,
            motion = MotionLevel.Reduced,
            logs = true,
            killSwitch = true,
            trustedNetworks = listOf("0011223344556677|Home Wi-Fi", "8899aabbccddeeff|Office | 2nd floor"),
        )
        val decoded = Settings.fromJson(JSONObject(original.toJson().toString()))
        assertEquals(original, decoded)
    }

    @Test
    fun `missing and unknown values fall back to defaults`() {
        val decoded = Settings.fromJson(JSONObject("""{"mode":"Warp","mtu":"x","palette":"Nope"}"""))
        assertEquals(Settings(), decoded)
    }

    @Test
    fun `out-of-range numbers are clamped rather than trusted`() {
        val decoded = Settings.fromJson(JSONObject("""{"mtu":100,"socksPort":80,"httpPort":99999}"""))
        assertEquals(1280, decoded.mtu)
        assertEquals(1024, decoded.socksPort)
        assertEquals(65535, decoded.httpPort)
    }

    @Test
    fun `connect targets encode and decode symmetrically`() {
        for (target in listOf(ConnectTarget.Fastest, ConnectTarget.Country("NL"), ConnectTarget.Specific("a1b2c3d4e5f60718"))) {
            assertEquals(target, ConnectTarget.decode(target.encode()))
        }
        assertEquals(ConnectTarget.Fastest, ConnectTarget.decode(null))
        assertEquals(ConnectTarget.Fastest, ConnectTarget.decode("garbage"))
    }

    @Test
    fun `server kind uses plain categories`() {
        val base = Server("k", "vless://x", "n", "vless", "tcp", "reality", "h", 443, "DE", "user")
        assertEquals(ServerKind.Direct, base.kind)
        assertEquals(ServerKind.Cdn, base.copy(transport = "ws", security = "tls").kind)
        assertEquals(ServerKind.Other, base.copy(transport = "tcp", security = "tls").kind)
        assertEquals(ServerKind.Quic, base.copy(protocol = "hysteria2", transport = "quic", security = "tls").kind)
        assertEquals(ServerKind.Quic, base.copy(protocol = "tuic", transport = "quic", security = "tls").kind)
        // XHTTP with an `extra` block is the split-path family, whatever its security.
        val xhttp = base.copy(transport = "xhttp", security = "tls")
        assertEquals(ServerKind.Split, xhttp.copy(link = "vless://id@h:443?type=xhttp&extra=%7B%7D#n").kind)
        assertEquals(ServerKind.Cdn, xhttp.copy(link = "vless://id@h:443?type=xhttp&extra=#n").kind)
        assertEquals(ServerKind.Cdn, xhttp.copy(link = "vless://id@h:443?type=xhttp#extra=1").kind)
    }

    @Test
    fun `crowd picks are marked as verified by others`() {
        val base = Server("k", "vless://x", "n", "vless", "tcp", "reality", "h", 443, "DE", "feed:crowd")
        assertEquals(true, base.crowdVerified)
        assertEquals(false, base.copy(source = "feed:discovered").crowdVerified)
    }

    @Test
    fun `trusted networks match by identity, not label`() {
        val s = Settings(trustedNetworks = listOf("0011223344556677|Home"))
        assertEquals(true, s.trusts("0011223344556677"))
        assertEquals(false, s.trusts("Home"))
        assertEquals(false, s.trusts(null))
        assertEquals("Home", s.trustedLabel("0011223344556677"))
        // Malformed or duplicate entries are dropped when read back.
        val decoded = Settings.fromJson(JSONObject("""{"trustedNetworks":["nolabel","a|One","a|Two"]}"""))
        assertEquals(listOf("a|One"), decoded.trustedNetworks)
    }
}
