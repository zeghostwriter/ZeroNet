package com.zeronet.mobile.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class SettingsTest {

    @Test
    fun `a saved Smart evasion level reads as Auto`() {
        val old = JSONObject().put("evasion", "Smart")
        assertEquals(EvasionLevel.Auto, Settings.fromJson(old).evasion)
    }

    @Test
    fun `the old tlshello default moves to 1-1 once, a later choice is kept`() {
        val old = JSONObject().put("fragmentPackets", "tlshello")
        assertEquals("1-1", Settings.fromJson(old).fragmentPackets)

        val chosen = Settings(fragmentPackets = "tlshello").toJson()
        assertEquals("tlshello", Settings.fromJson(chosen).fragmentPackets)
    }

    @Test
    fun `the old Google remote DNS default moves to Auto once, a later choice is kept`() {
        val old = JSONObject().put("remoteDns", "Google")
        assertEquals(RemoteDns.Auto, Settings.fromJson(old).remoteDns)

        val chosen = Settings(remoteDns = RemoteDns.Google).toJson()
        assertEquals(RemoteDns.Google, Settings.fromJson(chosen).remoteDns)
    }

    @Test
    fun `the old 1500 MTU default moves to 9000 once, a later choice is kept`() {
        val old = JSONObject().put("mtu", 1500)
        assertEquals(9000, Settings.fromJson(old).mtu)

        val chosen = Settings(mtu = 1500).toJson()
        assertEquals(1500, Settings.fromJson(chosen).mtu)
    }

    @Test
    fun `the old Medium speed floor default moves to Adaptive once, a later choice is kept`() {
        val old = JSONObject().put("speedFloor", "Medium")
        assertEquals(SpeedFloor.Adaptive, Settings.fromJson(old).speedFloor)

        val chosen = Settings(speedFloor = SpeedFloor.Medium).toJson()
        assertEquals(SpeedFloor.Medium, Settings.fromJson(chosen).speedFloor)
    }

    @Test
    fun `any fixed floor from a build that never recorded a choice moves to Adaptive, a custom number does not`() {
        for (name in listOf("Off", "Low", "Medium")) {
            val old = JSONObject().put("speedFloor", name)
            assertEquals(name, SpeedFloor.Adaptive, Settings.fromJson(old).speedFloor)
        }
        val custom = JSONObject().put("speedFloor", "Custom").put("speedFloorKbps", 2500)
        assertEquals(SpeedFloor.Custom, Settings.fromJson(custom).speedFloor)
        for (floor in listOf(SpeedFloor.Off, SpeedFloor.Low, SpeedFloor.Medium)) {
            assertEquals(floor, Settings.fromJson(Settings(speedFloor = floor).toJson()).speedFloor)
        }
    }

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
            warpConsent = WarpConsent.Off,
            warpOrder = WarpOrder.Reverse,
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
            speedFloor = SpeedFloor.Adaptive,
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

    /**
     * The Cloudflare answer is what a hand-edited file could most usefully
     * change, so anything that is not one of the three words reads as "not
     * answered yet" — which asks again rather than silently agreeing.
     */
    @Test
    fun `an unrecognised Cloudflare answer asks again instead of agreeing`() {
        assertEquals(WarpConsent.Ask, Settings().warpConsent)
        assertEquals(WarpConsent.Ask, Settings.fromJson(JSONObject("""{"warpConsent":"on"}""")).warpConsent)
        assertEquals(WarpConsent.Ask, Settings.fromJson(JSONObject("""{"warpConsent":"yes"}""")).warpConsent)
        assertEquals(WarpConsent.Ask, Settings.fromJson(JSONObject("""{"warpConsent":""}""")).warpConsent)
        for (answer in WarpConsent.entries) {
            assertEquals(answer, Settings.fromJson(Settings(warpConsent = answer).toJson()).warpConsent)
        }
    }

    @Test
    fun `the WARP order defaults to hybrid and survives a round trip`() {
        assertEquals(WarpOrder.Hybrid, Settings().warpOrder)
        assertEquals(WarpOrder.Hybrid, Settings.fromJson(JSONObject("""{"warpOrder":"sideways"}""")).warpOrder)
        for (order in WarpOrder.entries) {
            assertEquals(order, Settings.fromJson(Settings(warpOrder = order).toJson()).warpOrder)
        }
        // The core's spelling, which `warp_order` and the WARP job both read.
        assertEquals("server-first", WarpOrder.Hybrid.wire)
        assertEquals("warp-first", WarpOrder.Reverse.wire)
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
