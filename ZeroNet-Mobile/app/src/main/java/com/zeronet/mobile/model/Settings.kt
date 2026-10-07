package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONArray
import org.json.JSONObject

enum class ConnectionMode { Vpn, Proxy }

/**
 * How ZeroNet chooses and runs servers. See `Engine` for what each does.
 *
 * - [Normal] (recommended): encrypted servers with backups, and it does not
 *   give up: when the usual way finds nothing it goes on to every other route
 *   and method, fastest first (see `Ladder`).
 * - [Fast]: the first server that works; nothing else.
 * - [Gaming]: lowest and steadiest ping, UDP allowed, one server that is never
 *   switched mid-game. It gives up some security for that.
 * - [Legacy]: what Normal was before it learned to keep trying.
 */
enum class ConnectionProfile { Normal, Fast, Gaming, Legacy }

/** Whether the profile shapes servers and evasion the way the original Normal did. */
val ConnectionProfile.classic: Boolean get() = this == ConnectionProfile.Normal || this == ConnectionProfile.Legacy
/**
 * The answer to "may ZeroNet use Cloudflare WARP?".
 *
 * [Ask] shows the question once, on the first Normal-mode connect; answering
 * it moves the setting to [On] or [Off], so it is asked only the once.
 * [On] sets the hybrid account up without asking again; [Off] never uses
 * Cloudflare at all.
 */
enum class WarpConsent { Ask, On, Off }

/**
 * The order a WARP account and its servers are brought up in.
 *
 * [Hybrid] dials a found server first and reaches Cloudflare through it, so
 * the network only ever sees that server. [Reverse] dials Cloudflare first
 * and reaches a found server from inside it, which also reaches servers the
 * network blocks. [wire] is the core's spelling (`warp_order`).
 */
enum class WarpOrder(val wire: String) { Hybrid("server-first"), Reverse("warp-first") }

enum class AutoConnect { Off, OnAppStart, OnBoot }
enum class AppFilterMode { All, OnlySelected, AllExceptSelected }
/** How much ClientHello fragmenting to use. [Auto] tries each server as is
 *  first and fragmented if that fails, starting fragmented where other users
 *  reported that works better (it absorbed the old "Smart" level; a saved
 *  "Smart" reads as [Auto]). */
enum class EvasionLevel { Off, Auto, Strong }

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
    /** Learns the user's recently achieved speeds and drops a config that is
     *  really slow next to them; the floor is computed live, not fixed. */
    Adaptive(-2),
    Custom(-1),
}

enum class ThemeMode { System, Light, Dark }
enum class Palette { GoldenDark, Nightshade, Arctic, Sakura, Paper, Contrast }
enum class MotionLevel { Full, Reduced }
enum class AppLanguage { System, English, Persian, Azerbaijani, Kurdish, Arabic, Russian, Turkish, Chinese }
enum class RemoteDns { Auto, Cloudflare, Google, Quad9, AdGuard }

/** Iranian anti-sanction resolvers for services that block Iranian IPs. Mirrors
 *  zero-config `AntiSanctionDns`; [Off] resolves those names like any other. */
enum class AntiSanctionDns { Auto, Bertina, Shecan, Electro, Ipm, Begzar, Radar, Off }

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
    /** Whether ZeroNet may set up a Cloudflare WARP account (see [WarpConsent]). */
    val warpConsent: WarpConsent = WarpConsent.Ask,
    /** The order WARP accounts run in (see [WarpOrder]). */
    val warpOrder: WarpOrder = WarpOrder.Hybrid,
    val autoConnect: AutoConnect = AutoConnect.Off,
    val autoSwitch: Boolean = true,
    /** Move off a server whose live download speed stays under this. */
    val speedFloor: SpeedFloor = SpeedFloor.Adaptive,
    /** Threshold in kbps, used only when [speedFloor] is [SpeedFloor.Custom]. */
    val speedFloorKbps: Int = 3000,
    val ipv6: Boolean = false,
    /** The TUN ends in the in-process TCP stack, so this sizes only the hop
     *  inside the phone: 9000 carries about four times what 1500 does for
     *  the same CPU (measured, zero-tun/examples/mtu_bench.rs). The real
     *  network's packet size is handled per connection in the core. */
    val mtu: Int = 9000,
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
    val remoteDns: RemoteDns = RemoteDns.Auto,
    /** A user-supplied resolver that overrides [remoteDns] when non-blank.
     *  Accepts a bare IP (e.g. "8.8.8.8"), "tls://…", "https://…/dns-query". */
    val customDns: String = "",
    /** Domestic resolver for sanctioned services (OpenAI, GitHub, …) that block
     *  Iranian IPs; they resolve here and route direct. */
    val antiSanctionDns: AntiSanctionDns = AntiSanctionDns.Auto,
    /** A user-supplied anti-sanction resolver that overrides [antiSanctionDns]
     *  when non-blank. Same rule as [customDns]: an IP or IP-addressed DoH/DoT. */
    val customAntiSanction: String = "",
    /** ClientHello fragment writes for Strong/Smart evasion: a range like
     *  "1-1" (plain TCP segments, the default), or "tlshello", which stopped
     *  getting through in Iran in September 2026. */
    val fragmentPackets: String = "1-1",
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
            // Adaptive computes its floor live from recent speeds (Engine's
            // AdaptiveFloor); there is no static value to report here.
            SpeedFloor.Adaptive -> 0L
            SpeedFloor.Custom -> speedFloorKbps.coerceIn(0, 1_000_000).toLong() * 1_000L / 8
        }

    fun toJson(): JSONObject = JSONObject()
        .put("mode", mode.name)
        .put("profile", profile.name)
        .put("warpConsent", warpConsent.name)
        .put("warpOrder", warpOrder.name)
        .put("autoConnect", autoConnect.name)
        .put("autoSwitch", autoSwitch)
        .put("speedFloor", speedFloor.name)
        .put("speedFloorChosen", true)
        .put("speedFloorKbps", speedFloorKbps)
        .put("ipv6", ipv6)
        .put("mtu", mtu)
        .put("mtuChosen", true)
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
        .put("remoteDnsChosen", true)
        .put("customDns", customDns)
        .put("antiSanctionDns", antiSanctionDns.name)
        .put("antiSanctionChosen", true)
        .put("customAntiSanction", customAntiSanction)
        .put("fragmentPackets", fragmentPackets)
        .put("fragmentPacketsChosen", true)
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
                warpConsent = o.enumOr("warpConsent", d.warpConsent),
                warpOrder = o.enumOr("warpOrder", d.warpOrder),
                autoConnect = o.enumOr("autoConnect", d.autoConnect),
                autoSwitch = o.optBoolean("autoSwitch", d.autoSwitch),
                // Settings saved before Adaptive became the default never had a
                // choice recorded ("speedFloorChosen"): whatever fixed floor is
                // in them was the old default or a side effect, so they move
                // to Adaptive once. A choice saved since, and a custom number,
                // are kept.
                speedFloor = o.enumOr("speedFloor", d.speedFloor).let {
                    val fixed = it != SpeedFloor.Adaptive && it != SpeedFloor.Custom
                    if (fixed && !o.has("speedFloorChosen")) d.speedFloor else it
                },
                speedFloorKbps = o.optInt("speedFloorKbps", d.speedFloorKbps).coerceIn(0, 1_000_000),
                ipv6 = o.optBoolean("ipv6", d.ipv6),
                // 1500 saved before the measured default was the old default;
                // move it once. A choice saved since is kept.
                mtu = o.optInt("mtu", d.mtu).coerceIn(1280, 9000).let {
                    if (it == 1500 && !o.has("mtuChosen")) d.mtu else it
                },
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
                // Google saved before "Auto" existed was the old default;
                // move it once. A choice saved since is kept.
                remoteDns = o.enumOr("remoteDns", d.remoteDns).let {
                    if (it == RemoteDns.Google && !o.has("remoteDnsChosen")) d.remoteDns else it
                },
                customDns = o.optString("customDns", d.customDns),
                // Shecan saved before the measured "Auto" existed was the old
                // default; move it once. A choice saved since is kept.
                antiSanctionDns = o.enumOr("antiSanctionDns", d.antiSanctionDns).let {
                    if (it == AntiSanctionDns.Shecan && !o.has("antiSanctionChosen")) d.antiSanctionDns else it
                },
                customAntiSanction = o.optString("customAntiSanction", d.customAntiSanction),
                // "tlshello" saved before September 2026 was the old default,
                // which stopped getting through in Iran; move it to the new one
                // once. A choice saved since carries the marker and is kept.
                fragmentPackets = o.optString("fragmentPackets", d.fragmentPackets).let {
                    if (it == "tlshello" && !o.has("fragmentPacketsChosen")) d.fragmentPackets else it
                },
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
