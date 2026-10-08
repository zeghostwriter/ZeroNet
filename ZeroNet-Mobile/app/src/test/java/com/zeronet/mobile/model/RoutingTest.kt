package com.zeronet.mobile.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingTest {

    /** The JSON is the core's `UserRule`: the same keys, and only the ones in use. */
    @Test
    fun `a rule is written the way the core reads it`() {
        val rule = RoutingRule(
            action = RuleAction.Direct,
            domains = listOf("geosite:category-ir", "keyword:bank"),
            apps = listOf("org.telegram.messenger"),
            port = "443",
            network = RuleNetwork.Tcp,
            enabled = false,
        )
        val json = rule.toJson()
        assertEquals("direct", json.getString("action"))
        assertEquals("org.telegram.messenger", json.getJSONArray("process").getString(0))
        assertEquals("tcp", json.getString("network"))
        assertFalse(json.getBoolean("enabled"))
        assertFalse(json.has("ip"))
        assertEquals(rule, RoutingRule.fromJson(json))
        // On and for both kinds of traffic, neither is written.
        val plain = RoutingRule(domains = listOf("a.example")).toJson()
        assertFalse(plain.has("enabled") || plain.has("network"))
    }

    @Test
    fun `a rule needs something to match and ports that are ports`() {
        assertEquals(RuleProblem.Empty, RoutingRule().problem())
        assertNull(RoutingRule(port = "443").problem())
        assertNull(RoutingRule(port = "80,443,1000-2000").problem())
        assertEquals(RuleProblem.Port, RoutingRule(port = "70000").problem())
        assertEquals(RuleProblem.Port, RoutingRule(port = "2000-1000").problem())
        assertEquals(RuleProblem.Port, RoutingRule(port = "80,").problem())
        assertEquals(listOf("a.example", "b.example"), RoutingRule.entries(" a.example,b.example\n a.example "))
    }

    @Test
    fun `profiles survive saving and the active one gives its rules`() {
        val work = RoutingProfile("Work", listOf(RoutingRule(domains = listOf("a.example"))))
        val settings = Settings(routingProfiles = listOf(work, RoutingProfile("Home")), routingProfile = "Work")
        val back = Settings.fromJson(JSONObject(settings.toJson().toString()))
        assertEquals(settings.routingProfiles, back.routingProfiles)
        assertEquals("Work", back.routingProfile)
        assertEquals(work.rules, back.activeRoutingRules)
        assertTrue(back.copy(routingProfile = "").activeRoutingRules.isEmpty())
        assertTrue(back.copy(routingProfile = "Gone").activeRoutingRules.isEmpty())
        // Older settings without profiles read as none.
        assertTrue(Settings.fromJson(JSONObject()).routingProfiles.isEmpty())
    }
}
