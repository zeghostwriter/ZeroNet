package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.theme.ZeroColors
import com.zeronet.mobile.ui.util.highlightLink
import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkColorTest {
    private val c = ZeroColors(
        isDark = true, bg = Color.Black, surface = Color.Black, surfaceHi = Color.Black, border = Color.Gray,
        muted = Color.Gray, text = Color.White, accent = Color.Cyan, accentBright = Color.Blue,
        accentDim = Color.DarkGray, accentHot = Color.Magenta, onAccent = Color.Black,
        ok = Color.Green, warn = Color.Yellow, err = Color.Red, info = Color.LightGray,
    )

    @Test
    fun `the coloured text is exactly the link`() {
        for (uri in listOf(
            "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=reality&sni=a.b&fp=chrome#🇩🇪 Frankfurt",
            "trojan://secret@example.com:8443?security=tls&sni=e.com#Node",
            "vmess://eyJhIjoiYiJ9",
            "ss://YWVzOnB3@[2001:db8::1]:8388#v6",
            "not-a-link",
            "",
        )) {
            assertEquals(uri, highlightLink(uri, c).text)
        }
    }

    @Test
    fun `host port and name get their own colours`() {
        val text = highlightLink("vless://uuid@host.example:443?type=tcp#My Node", c)
        fun colorOf(part: String): Color? {
            val start = text.text.indexOf(part)
            return text.spanStyles.firstOrNull { it.start == start && it.end == start + part.length }?.item?.color
        }
        assertEquals(c.warn, colorOf("uuid"))
        assertEquals(c.accentBright, colorOf("host.example"))
        assertEquals(c.info, colorOf("443"))
        assertEquals(c.ok, colorOf("My Node"))
        assertTrue(text.spanStyles.isNotEmpty())
    }
}
