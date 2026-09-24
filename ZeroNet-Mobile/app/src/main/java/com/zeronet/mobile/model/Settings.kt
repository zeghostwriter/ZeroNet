package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONArray
import org.json.JSONObject

enum class ConnectionMode { Vpn, Proxy }
enum class AutoConnect { Off, OnAppStart, OnBoot }
enum class AppFilterMode { All, OnlySelected, AllExceptSelected }
enum class EvasionLevel { Off, Auto, Strong }
enum class ThemeMode { System, Light, Dark }
enum class Palette { GoldenDark, Nightshade, Arctic, Sakura, Paper, Contrast }
enum class MotionLevel { Full, Reduced }
enum class AppLanguage { System, English, Persian }
enum class RemoteDns { Cloudflare, Google, Quad9, AdGuard }

/**
 * Every user preference, as one immutable value. The UI process owns it
 * (SharedPreferences); the :vpn process receives a JSON copy with each
 * connect request and in `connect_options.json` for the tile and boot
 * receiver, so the two processes never share a preferences file.
 */
@Immutable
data class Settings(
    // Connection
    val mode: ConnectionMode = ConnectionMode.Vpn,
    val autoConnect: AutoConnect = AutoConnect.Off,
    val autoSwitch: Boolean = true,
    val ipv6: Boolean = false,
    val mtu: Int = 1500,
    // Servers & sources
    val lastTarget: String = "fastest",
    val disabledSources: Set<String> = emptySet(),
    val preferredCountries: List<String> = emptyList(),
    val autoRefresh: Boolean = true,
    // Split tunnelling
    val iranDirect: Boolean = true,
    val bypassLan: Boolean = true,
    val appFilter: AppFilterMode = AppFilterMode.All,
    val filteredApps: Set<String> = emptySet(),
    // Sharing
    val lanShare: Boolean = false,
    val socksPort: Int = 10808,
    val httpPort: Int = 10809,
    val lanUser: String = "",
    val lanPass: String = "",
    // Anti-censorship
    val evasion: EvasionLevel = EvasionLevel.Auto,
    val blockQuic: Boolean = true,
    val remoteDns: RemoteDns = RemoteDns.Google,
    /** A user-supplied resolver that overrides [remoteDns] when non-blank.
     *  Accepts a bare IP (e.g. "8.8.8.8"), "tls://…", "https://…/dns-query". */
    val customDns: String = "",
    val fakeDns: Boolean = true,
    val blockAds: Boolean = true,
    // Appearance
    val themeMode: ThemeMode = ThemeMode.System,
    val palette: Palette = Palette.GoldenDark,
    val dynamicColor: Boolean = false,
    val amoled: Boolean = false,
    val language: AppLanguage = AppLanguage.System,
    val motion: MotionLevel = MotionLevel.Full,
    // Privacy
    val logs: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("mode", mode.name)
        .put("autoConnect", autoConnect.name)
        .put("autoSwitch", autoSwitch)
        .put("ipv6", ipv6)
        .put("mtu", mtu)
        .put("lastTarget", lastTarget)
        .put("disabledSources", JSONArray(disabledSources.toList()))
        .put("preferredCountries", JSONArray(preferredCountries))
        .put("autoRefresh", autoRefresh)
        .put("iranDirect", iranDirect)
        .put("bypassLan", bypassLan)
        .put("appFilter", appFilter.name)
        .put("filteredApps", JSONArray(filteredApps.toList()))
        .put("lanShare", lanShare)
        .put("socksPort", socksPort)
        .put("httpPort", httpPort)
        .put("lanUser", lanUser)
        .put("lanPass", lanPass)
        .put("evasion", evasion.name)
        .put("blockQuic", blockQuic)
        .put("remoteDns", remoteDns.name)
        .put("customDns", customDns)
        .put("fakeDns", fakeDns)
        .put("blockAds", blockAds)
        .put("themeMode", themeMode.name)
        .put("palette", palette.name)
        .put("dynamicColor", dynamicColor)
        .put("amoled", amoled)
        .put("language", language.name)
        .put("motion", motion.name)
        .put("logs", logs)

    companion object {
        fun fromJson(o: JSONObject): Settings {
            val d = Settings()
            return Settings(
                mode = o.enumOr("mode", d.mode),
                autoConnect = o.enumOr("autoConnect", d.autoConnect),
                autoSwitch = o.optBoolean("autoSwitch", d.autoSwitch),
                ipv6 = o.optBoolean("ipv6", d.ipv6),
                mtu = o.optInt("mtu", d.mtu).coerceIn(1280, 9000),
                lastTarget = o.optString("lastTarget", d.lastTarget),
                disabledSources = o.strings("disabledSources").toSet(),
                preferredCountries = o.strings("preferredCountries"),
                autoRefresh = o.optBoolean("autoRefresh", d.autoRefresh),
                iranDirect = o.optBoolean("iranDirect", d.iranDirect),
                bypassLan = o.optBoolean("bypassLan", d.bypassLan),
                appFilter = o.enumOr("appFilter", d.appFilter),
                filteredApps = o.strings("filteredApps").toSet(),
                lanShare = o.optBoolean("lanShare", d.lanShare),
                socksPort = o.optInt("socksPort", d.socksPort).coerceIn(1024, 65535),
                httpPort = o.optInt("httpPort", d.httpPort).coerceIn(1024, 65535),
                lanUser = o.optString("lanUser", d.lanUser),
                lanPass = o.optString("lanPass", d.lanPass),
                evasion = o.enumOr("evasion", d.evasion),
                blockQuic = o.optBoolean("blockQuic", d.blockQuic),
                remoteDns = o.enumOr("remoteDns", d.remoteDns),
                customDns = o.optString("customDns", d.customDns),
                fakeDns = o.optBoolean("fakeDns", d.fakeDns),
                blockAds = o.optBoolean("blockAds", d.blockAds),
                themeMode = o.enumOr("themeMode", d.themeMode),
                palette = o.enumOr("palette", d.palette),
                dynamicColor = o.optBoolean("dynamicColor", d.dynamicColor),
                amoled = o.optBoolean("amoled", d.amoled),
                language = o.enumOr("language", d.language),
                motion = o.enumOr("motion", d.motion),
                logs = o.optBoolean("logs", d.logs),
            )
        }

        private inline fun <reified E : Enum<E>> JSONObject.enumOr(key: String, fallback: E): E =
            optString(key, "").let { name -> enumValues<E>().firstOrNull { it.name == name } } ?: fallback

        private fun JSONObject.strings(key: String): List<String> {
            val array = optJSONArray(key) ?: return emptyList()
            return List(array.length()) { array.optString(it) }.filter { it.isNotBlank() }
        }
    }
}
