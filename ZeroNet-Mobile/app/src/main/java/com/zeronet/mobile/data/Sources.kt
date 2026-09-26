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
        FeedSource("limilco", "liMilCo", "liMilCo/v2r", "$RAW/liMilCo/v2r/main/new_configs.txt", 1),
        FeedSource("sinavm", "SVM", "sinavm/SVM", "$RAW/sinavm/SVM/main/lite/subscriptions/xray/base64/mix", 1),
        FeedSource("anonymou3", "Multi Proxy (tested)", "4n0nymou3/multi-proxy-config-fetcher", "$RAW/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt", 1),
        FeedSource("radikal", "0xRadikal", "0xRadikal/Free-v2ray-Configs", "$RAW/0xRadikal/Free-v2ray-Configs/main/all/configs.txt", 2),
        FeedSource("epodonios", "Epodonios", "Epodonios/v2ray-configs", "$RAW/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", 2),
        FeedSource("delta", "Delta-Kronecker", "Delta-Kronecker/V2ray-Config", "$RAW/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt", 3),
        FeedSource("mheidari", "mheidari98", "mheidari98/.proxy", "$RAW/mheidari98/.proxy/main/all", 3),
        FeedSource("f0rc3run", "F0rc3Run", "F0rc3Run/F0rc3Run", "$RAW/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt", 3),
    )

    fun enabled(disabled: Set<String>, maxTier: Int = 3): List<FeedSource> =
        builtIn.filter { it.id !in disabled && it.tier <= maxTier }

    fun toJson(sources: List<FeedSource>): JSONArray = JSONArray().also { a -> sources.forEach { a.put(it.toJson()) } }
}
