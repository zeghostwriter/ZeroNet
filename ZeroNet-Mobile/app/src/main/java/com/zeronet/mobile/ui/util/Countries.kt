package com.zeronet.mobile.ui.util

import android.graphics.Paint
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

object Countries {
    private val glyphCache = ConcurrentHashMap<String, Boolean>()
    private val probe = Paint()

    /** "DE" → 🇩🇪 (two regional-indicator symbols), or "" for anything that is not an ISO alpha-2 code. */
    fun flag(code: String): String {
        if (code.length != 2 || !code.all { it in 'A'..'Z' || it in 'a'..'z' }) return ""
        val upper = code.uppercase(Locale.ROOT)
        val first = 0x1F1E6 + (upper[0] - 'A')
        val second = 0x1F1E6 + (upper[1] - 'A')
        return String(Character.toChars(first)) + String(Character.toChars(second))
    }

    /**
     * Whether this device's fonts can draw [emoji] as one glyph. Old or
     * stripped-down system fonts render flags as two boxed letters; the UI
     * then shows the country code in a badge instead.
     */
    fun canDraw(emoji: String): Boolean {
        if (emoji.isEmpty()) return false
        return glyphCache.getOrPut(emoji) {
            runCatching { synchronized(probe) { probe.hasGlyph(emoji) } }.getOrDefault(false)
        }
    }

    /** Country name in the UI language ("Germany" / "آلمان"), or "" when unknown. */
    fun name(code: String, locale: Locale): String {
        if (code.length != 2) return ""
        val region = runCatching { Locale.Builder().setRegion(code.uppercase(Locale.ROOT)).build() }.getOrNull() ?: return ""
        val name = region.getDisplayCountry(locale)
        return if (name.isBlank() || name.equals(code, ignoreCase = true)) "" else name
    }

    /** Countries offered as preferences even before any server from them was seen. */
    val COMMON = listOf("DE", "NL", "FI", "FR", "GB", "SE", "TR", "AE", "US", "CA", "JP", "SG", "AM", "RU")
}
