package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONArray
import org.json.JSONObject

/** Where a [RoutingRule] sends what it matches. [wire] is the core's spelling. */
enum class RuleAction(val wire: String) { Proxy("proxy"), Direct("direct"), Block("block") }

/** Which kind of traffic a [RoutingRule] covers; "" in the core means both. */
enum class RuleNetwork(val wire: String) { Any(""), Tcp("tcp"), Udp("udp") }

/**
 * One rule of a routing profile: the phone's copy of the core's `UserRule`
 * (crates/zero-config/src/presets.rs), with the same JSON, so the core reads
 * it as it is.
 *
 * Every list uses Xray's syntax: domains as `example.com` (and its
 * subdomains), `full:`, `keyword:`, `regexp:` or `geosite:`; addresses as an
 * IP, a CIDR range or `geoip:`; apps by package name. Whatever is filled in
 * must all match, and any entry of a list may. A rule needs a domain, an
 * address, an app or a port ([problem]).
 */
@Immutable
data class RoutingRule(
    val action: RuleAction = RuleAction.Proxy,
    val domains: List<String> = emptyList(),
    val addresses: List<String> = emptyList(),
    val apps: List<String> = emptyList(),
    /** `443`, `80,443` or `1000-2000`; empty for any. */
    val port: String = "",
    val network: RuleNetwork = RuleNetwork.Any,
    val enabled: Boolean = true,
) {
    /** What is wrong with the rule, or null when the core will use it. */
    fun problem(): RuleProblem? = when {
        domains.isEmpty() && addresses.isEmpty() && apps.isEmpty() && port.isBlank() -> RuleProblem.Empty
        port.isNotBlank() && !validPorts(port) -> RuleProblem.Port
        else -> null
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("action", action.wire)
        if (domains.isNotEmpty()) put("domain", JSONArray(domains))
        if (addresses.isNotEmpty()) put("ip", JSONArray(addresses))
        if (apps.isNotEmpty()) put("process", JSONArray(apps))
        if (port.isNotBlank()) put("port", port.trim())
        if (network != RuleNetwork.Any) put("network", network.wire)
        if (!enabled) put("enabled", false)
    }

    companion object {
        fun fromJson(o: JSONObject): RoutingRule = RoutingRule(
            action = RuleAction.entries.firstOrNull { it.wire == o.optString("action") } ?: RuleAction.Proxy,
            domains = o.strings("domain"),
            addresses = o.strings("ip"),
            apps = o.strings("process"),
            port = o.optString("port", ""),
            network = RuleNetwork.entries.firstOrNull { it.wire == o.optString("network", "") } ?: RuleNetwork.Any,
            enabled = o.optBoolean("enabled", true),
        )

        /** Split what the user typed into entries: commas, spaces or new lines between them. */
        fun entries(text: String): List<String> =
            text.split(',', '\n', ' ').map { it.trim() }.filter { it.isNotEmpty() }.distinct()

        /** `443`, `80,443`, `1000-2000`, each part 1 to 65535 with the range in order. */
        fun validPorts(text: String): Boolean = text.split(',').all { part ->
            val bounds = part.trim().split('-')
            val numbers = bounds.map { it.trim().toIntOrNull() ?: return@all false }
            numbers.size in 1..2 && numbers.all { it in 1..65535 } && numbers.first() <= numbers.last()
        }

        private fun JSONObject.strings(key: String): List<String> {
            val array = optJSONArray(key) ?: return emptyList()
            return List(array.length()) { array.optString(it).trim() }.filter { it.isNotEmpty() }
        }
    }
}

enum class RuleProblem { Empty, Port }

/** A named list of [RoutingRule]s; one is in use at a time, or none. */
@Immutable
data class RoutingProfile(val name: String, val rules: List<RoutingRule> = emptyList()) {
    fun toJson(): JSONObject = JSONObject()
        .put("name", name)
        .put("rules", JSONArray(rules.map { it.toJson() }))

    companion object {
        fun fromJson(o: JSONObject): RoutingProfile? {
            val name = o.optString("name", "").trim().ifEmpty { return null }
            val rules = o.optJSONArray("rules")
            return RoutingProfile(
                name,
                if (rules == null) emptyList() else List(rules.length()) { rules.optJSONObject(it) }
                    .filterNotNull().map(RoutingRule::fromJson),
            )
        }

        fun listFromJson(array: JSONArray?): List<RoutingProfile> {
            if (array == null) return emptyList()
            return List(array.length()) { array.optJSONObject(it) }
                .filterNotNull().mapNotNull(::fromJson).distinctBy { it.name }
        }
    }
}
