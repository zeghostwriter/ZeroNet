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
            fakeDns = false,
            blockAds = false,
            themeMode = ThemeMode.Dark,
            palette = Palette.Arctic,
            dynamicColor = true,
            amoled = true,
            language = AppLanguage.Persian,
            motion = MotionLevel.Reduced,
            logs = true,
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
    }
}
