package com.zeronet.mobile.service

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrowdFragmentFirstTest {

    private fun rankings(net: String, vararg methods: Triple<String, Double, Int>) = JSONObject().put(
        "nets",
        JSONObject().put(
            net,
            JSONObject().put("methods", JSONArray().also { a ->
                methods.forEach { (id, score, reporters) ->
                    a.put(JSONObject().put("id", id).put("score", score).put("reporters", reporters))
                }
            }),
        ),
    )

    @Test
    fun `fragmenting that clearly beats plain here starts first`() {
        val r = rankings("asn:206065", Triple("tls:fragment", 0.8, 5), Triple("tls:plain", 0.1, 5))
        assertTrue(Crowd.fragmentFirst(r, "asn:206065"))
    }

    @Test
    fun `a close race or a single reporter does not flip the order`() {
        assertFalse(Crowd.fragmentFirst(rankings("asn:1", Triple("tls:fragment", 0.6, 5), Triple("tls:plain", 0.55, 5)), "asn:1"))
        assertFalse(Crowd.fragmentFirst(rankings("asn:1", Triple("tls:fragment", 0.9, 1), Triple("tls:plain", 0.0, 5)), "asn:1"))
    }

    @Test
    fun `no data means plain first`() {
        assertFalse(Crowd.fragmentFirst(JSONObject(), "asn:1"))
        assertFalse(Crowd.fragmentFirst(rankings("asn:2", Triple("tls:fragment", 0.9, 5)), "asn:1"))
    }
}
