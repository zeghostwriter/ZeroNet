package com.zeronet.mobile.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.io.encoding.Base64

class WarpLinksTest {
    private fun link(json: String, padded: Boolean = false): String {
        val body = Base64.UrlSafe.encode(json.encodeToByteArray())
        return "warp://" + (if (padded) body else body.trimEnd('=')) + "#WARP"
    }

    @Test fun anAccountWithAnInnerDeviceRunsWarpInsideWarp() {
        val json = """{"route":"auto","masque":{"privateKey":"x"},"inner":{"privateKey":"y","reserved":[1,2,3]}}"""
        assertTrue(WarpLinks.hasInner(link(json)))
        assertTrue(WarpLinks.hasInner(link(json, padded = true)))
        assertTrue(WarpLinks.hasInner(link("""{"inner" : {"privateKey":"y"}}""")))
    }

    @Test fun olderAccountsAndOtherLinksDoNot() {
        assertFalse(WarpLinks.hasInner(link("""{"route":"auto","masque":{"privateKey":"x"}}""")))
        // The word on its own is not the block.
        assertFalse(WarpLinks.hasInner(link("""{"remark":"inner"}""")))
        assertFalse(WarpLinks.hasInner("vless://uuid@host:443#inner"))
        assertFalse(WarpLinks.hasInner("warp://!!!not-base64"))
        assertFalse(WarpLinks.hasInner("warp://"))
    }
}
