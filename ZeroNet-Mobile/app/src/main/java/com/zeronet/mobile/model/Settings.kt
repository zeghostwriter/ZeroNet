package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONArray
import org.json.JSONObject

enum class ConnectionMode { Vpn, Proxy }

/**
 * How ZeroNet chooses and runs servers. See `Engine` for what each does.
 *
 * - [Normal]: encrypted (TLS / REALITY) servers only, with backups.
 * - [Fast]: the first server that works; nothing else.
 * - [Gaming]: lowest ping, UDP allowed, one server that is never switched mid-game.
 */
enum class ConnectionProfile { Normal, Fast, Gaming }
enum class AutoConnect { Off, OnAppStart, OnBoot }
enum class AppFilterMode { All, OnlySelected, AllExceptSelected }
enum class EvasionLevel { Off, Auto, Strong, Smart }

/**
 * Slowest download ZeroNet tolerates before moving to another server.
 *
 * Only real traffic is measured: a config counts as slow while the phone is
 * actually moving data, never while idle. Numbers are the floor in Mbps;
 * [Custom] uses [Settings.speedFloorKbps].
 */
enum class SpeedFloor(val mbps: Int) {
    Off(0),
    Low(1),
    Medium(3),
    Custom(-1),
}

enum class ThemeMode { System, Light, Dark }
enum class Palette { GoldenDark, Nightshade, Arctic, Sakura, Paper, Contrast }
enum class MotionLevel { Full, Reduced }
enum class AppLanguage { System, English, Persian, Azerbaijani, Kurdish, Arabic, Russian, Turkish, Chinese }
enum class RemoteDns { Cloudflare, Google, Quad9, AdGuard }

/** Iranian anti-sanction resolvers for services that block Iranian IPs. Mirrors
 *  zero-config `AntiSanctionDns`; [Off] resolves those names like any other. */
enum class AntiSanctionDns { Shecan, Electro, Begzar, Radar, Off }

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
    val profile: ConnectionProfile = ConnectionProfile.Normal,
    val autoConnect: AutoConnect = AutoConnect.Off,
    val autoSwitch: Boolean = true,
    /** Move off a server whose live download speed stays under this. */
    val speedFloor: SpeedFloor = SpeedFloor.Medium,
    /** Threshold in kbps, used only when [speedFloor] is [SpeedFloor.Custom]. */
    val speedFloorKbps: Int = 3000,
    val ipv6: Boolean = false,
    val mtu: Int = 1500,
    /**
     * Keep the VPN interface up and drop traffic whenever no server carries
     * it: while searching, while the core restarts, and after a failed
     * connect (the engine keeps retrying). Nothing leaves the phone outside
     * the tunnel. Android's own "Block connections without VPN" does the same
     * at the system level, but not every ROM offers it.
     */
    val killSwitch: Boolean = false,
    /**
     * Networks where ZeroNet stays off: no automatic connect on them, and a
     * running tunnel disconnects on joining one. Entries are
     * `<NetworkIdentity hash>|<label shown in the UI>`.
     */
    val trustedNetworks: List<String> = emptyList(),
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
    /** Domestic resolver for sanctioned services (OpenAI, GitHub, …) that block
     *  Iranian IPs; they resolve here and route direct. */
    val antiSanctionDns: AntiSanctionDns = AntiSanctionDns.Shecan,
    /** A user-supplied anti-sanction resolver that overrides [antiSanctionDns]
     *  when non-blank. Same rule as [customDns]: an IP or IP-addressed DoH/DoT. */
    val customAntiSanction: String = "",
    /** ClientHello fragment writes for Strong/Smart evasion: "tlshello", or a
     *  range like "1-1" as a fallback when tlshello stops getting through. */
    val fragmentPackets: String = "tlshello",
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
    /** Share which public servers and clean addresses worked here, anonymously (see `Crowd`). */
    val shareResults: Boolean = true,
) {
    /**
     * The slow threshold in bytes per second; 0 disables speed switching.
     * Mbps is a network unit (10^6 bits), so the byte rate is an eighth.
     */
    /** Whether [networkId] (a [com.zeronet.mobile.data.NetworkIdentity] hash) is one the user trusts. */
    fun trusts(networkId: String?): Boolean =
        networkId != null && trustedNetworks.any { it.substringBefore('|') == networkId }

    /** The label the user saw when trusting [networkId], or "" when it is not trusted. */
    fun trustedLabel(networkId: String?): String =
        trustedNetworks.firstOrNull { it.substringBefore('|') == networkId }?.substringAfter('|').orEmpty()

    val speedFloorBytes: Long
        get() = when (speedFloor) {
            SpeedFloor.Off -> 0L
            SpeedFloor.Low, SpeedFloor.Medium -> speedFloor.mbps * 1_000_000L / 8
            SpeedFloor.Custom -> speedFloorKbps.coerceIn(0, 1_000_000).toLong() * 1_000L / 8
        }

    fun toJson(): JSONObject = JSONObject()
        .put("mode", mode.name)
        .put("profile", profile.name)
        .put("autoConnect", autoConnect.name)
        .put("autoSwitch", autoSwitch)
        .put("speedFloor", speedFloor.name)
        .put("speedFloorKbps", speedFloorKbps)
        .put("ipv6", ipv6)
        .put("mtu", mtu)
        .put("killSwitch", killSwitch)
        .put("trustedNetworks", JSONArray(trustedNetworks))
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
        .put("antiSanctionDns", antiSanctionDns.name)
        .put("customAntiSanction", customAntiSanction)
        .put("fragmentPackets", fragmentPackets)
        .put("fakeDns", fakeDns)
        .put("blockAds", blockAds)
        .put("themeMode", themeMode.name)
        .put("palette", palette.name)
        .put("dynamicColor", dynamicColor)
        .put("amoled", amoled)
        .put("language", language.name)
        .put("motion", motion.name)
        .put("logs", logs)
        .put("shareResults", shareResults)

    companion object {
        fun fromJson(o: JSONObject): Settings {
            val d = Settings()
            return Settings(
                mode = o.enumOr("mode", d.mode),
                profile = o.enumOr("profile", d.profile),
                autoConnect = o.enumOr("autoConnect", d.autoConnect),
                autoSwitch = o.optBoolean("autoSwitch", d.autoSwitch),
                speedFloor = o.enumOr("speedFloor", d.speedFloor),
                speedFloorKbps = o.optInt("speedFloorKbps", d.speedFloorKbps).coerceIn(0, 1_000_000),
                ipv6 = o.optBoolean("ipv6", d.ipv6),
                mtu = o.optInt("mtu", d.mtu).coerceIn(1280, 9000),
                killSwitch = o.optBoolean("killSwitch", d.killSwitch),
                trustedNetworks = o.strings("trustedNetworks").filter { '|' in it }.distinctBy { it.substringBefore('|') },
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
                antiSanctionDns = o.enumOr("antiSanctionDns", d.antiSanctionDns),
                customAntiSanction = o.optString("customAntiSanction", d.customAntiSanction),
                fragmentPackets = o.optString("fragmentPackets", d.fragmentPackets),
                fakeDns = o.optBoolean("fakeDns", d.fakeDns),
                blockAds = o.optBoolean("blockAds", d.blockAds),
                themeMode = o.enumOr("themeMode", d.themeMode),
                palette = o.enumOr("palette", d.palette),
                dynamicColor = o.optBoolean("dynamicColor", d.dynamicColor),
                amoled = o.optBoolean("amoled", d.amoled),
                language = o.enumOr("language", d.language),
                motion = o.enumOr("motion", d.motion),
                logs = o.optBoolean("logs", d.logs),
                shareResults = o.optBoolean("shareResults", d.shareResults),
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
