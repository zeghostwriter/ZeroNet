package com.zeronet.mobile.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * Community config feeds on GitHub, tiered by what measurement from inside
 * Iran showed (PLAN.md §3). Tier 0 is this project's own tested list. Tier 1
 * is fetched on every cold connect (when tier 0 was not enough) and is
 * small; tier 2 only when tier 1 did not yield enough working configs; tier 3
 * only when the user asks to search harder.
 */
data class FeedSource(
    val id: String,
    val name: String,
    val repo: String,
    val url: String,
    val tier: Int,
    /** Detached-signature URL (`<url>.sig`); set for the project's own signed list. */
    val sigUrl: String? = null,
) {
    fun toJson(): JSONObject = JSONObject().put("id", id).put("url", url).put("tier", tier)
        .apply { if (sigUrl != null) put("sig_url", sigUrl) }
}

object Sources {
    private const val RAW = "https://raw.githubusercontent.com"

    val builtIn: List<FeedSource> = listOf(
        // Tested every two hours by the harvest workflow and published by
        // this project: only working, encrypted configs, a few hundred at
        // most. Tier 0, so the search tries it before any other feed and,
        // when it yields enough, never downloads the big ones. Served from
        // jsDelivr, which is often reachable when raw.githubusercontent.com
        // is not.
        FeedSource("zeronet", "ZeroNet verified", "zeghostwriter/ZeroNet", "https://cdn.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/verified.txt", 0, "https://cdn.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/verified.txt.sig"),
        // Tier 1: fetched on every cold search that tier 0 did not satisfy, so
        // the whole tier is kept near 90 KB gzipped (sizes noted below).
        FeedSource("sinavm", "SVM", "sinavm/SVM", "$RAW/sinavm/SVM/main/lite/subscriptions/xray/base64/mix", 1),
        FeedSource("anonymou3", "Multi Proxy (tested)", "4n0nymou3/multi-proxy-config-fetcher", "$RAW/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt", 1),
        // Speed-tested before publish: a few hundred proven servers, so a cold
        // search is likelier to find a fast one without downloading a big list.
        FeedSource("matin", "v2ray-configs (best tested)", "MatinGhanbari/v2ray-configs", "$RAW/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", 1),
        FeedSource("roosterkid", "OpenProxyList (hourly)", "roosterkid/openproxylist", "$RAW/roosterkid/openproxylist/main/V2RAY_RAW.txt", 1),
        FeedSource("yebekhe", "vpn-fail", "yebekhe/vpn-fail", "$RAW/yebekhe/vpn-fail/main/sub-link", 1),
        FeedSource("mahdi0024", "ProxyCollector (Iran)", "Mahdi0024/ProxyCollector", "$RAW/Mahdi0024/ProxyCollector/master/sub/proxies.txt", 1),
        FeedSource("norouzi", "Iran configs (working)", "MrAbolfazlNorouzi/iran-configs", "$RAW/MrAbolfazlNorouzi/iran-configs/main/configs/working-configs.txt", 1),
        // Configs that still pass on Irancell, which fails differently from the
        // fixed-line providers.
        FeedSource("irancell", "Irancell configs", "morteza-v2/free-v2ray-irancell-config", "$RAW/morteza-v2/free-v2ray-irancell-config/main/Sub1.txt", 1),
        // Tier 2: only when tier 1 fell short (~440 KB in total).
        FeedSource("limilco", "liMilCo", "liMilCo/v2r", "$RAW/liMilCo/v2r/main/new_configs.txt", 2),
        FeedSource("solvpn", "SolVPN (tested)", "SoliSpirit/SolVPN", "$RAW/SoliSpirit/SolVPN/main/all_configs.txt", 2),
        FeedSource("miladtahanian", "Config-Collector (Iran)", "miladtahanian/Config-Collector", "$RAW/miladtahanian/Config-Collector/main/mixed_iran.txt", 2),
        FeedSource("f0rc3run", "F0rc3Run", "F0rc3Run/F0rc3Run", "$RAW/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt", 2),
        FeedSource("bahemmat", "V2ray-Collector (Iran)", "MohammadBahemmat/V2ray-Collector", "$RAW/MohammadBahemmat/V2ray-Collector/main/all_servers.txt", 2),
        // Tier 3: only when asked to search harder (~820 KB in total). The
        // multi-megabyte aggregators are not here on purpose: the server-side
        // harvest tests them and their results reach the phone as tier 0.
        FeedSource("epodonios", "Epodonios", "Epodonios/v2ray-configs", "$RAW/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", 3),
        FeedSource("mahdibland", "V2RayAggregator (speed-tested)", "mahdibland/V2RayAggregator", "$RAW/mahdibland/V2RayAggregator/master/sub/sub_merge.txt", 3),
        FeedSource("freedom", "Freedom-V2Ray", "MahanKenway/Freedom-V2Ray", "$RAW/MahanKenway/Freedom-V2Ray/main/configs/mix.txt", 3),
        FeedSource("proxykma", "proxykma (Iran)", "amirkma/proxykma", "$RAW/amirkma/proxykma/main/mix.txt", 3),
        FeedSource("vpnclashfa", "VPNClashFa (Iran)", "10ium/VpnClashFaCollector", "$RAW/10ium/VpnClashFaCollector/main/sub/all/mixed.txt", 3),
        FeedSource("autoaivpn", "AutoAiVPN (Iran)", "penhandev/AutoAiVPN", "$RAW/penhandev/AutoAiVPN/main/iran.txt", 3),
    )

    fun enabled(disabled: Set<String>, maxTier: Int = 3): List<FeedSource> =
        builtIn.filter { it.id !in disabled && it.tier <= maxTier }

    fun toJson(sources: List<FeedSource>): JSONArray = JSONArray().also { a -> sources.forEach { a.put(it.toJson()) } }
}
