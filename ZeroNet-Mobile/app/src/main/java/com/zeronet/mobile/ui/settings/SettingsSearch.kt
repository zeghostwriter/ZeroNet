package com.zeronet.mobile.ui.settings

import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import androidx.compose.runtime.Stable
import java.util.Locale

/**
 * Settings search matches every title and keyword in English and in Persian,
 * whatever the UI language is: a Persian user may type "DNS", an English one
 * may paste a Persian word from a guide.
 */
@Stable
class SettingsSearchIndex(context: Context) {
    private val sources: List<Resources> = listOf(
        context.resources,
        localized(context, Locale.ENGLISH),
        localized(context, Locale.forLanguageTag("fa")),
    )
    private val cache = HashMap<Int, String>()

    private fun text(id: Int): String = cache.getOrPut(id) {
        sources.joinToString("\n") { res -> runCatching { res.getString(id) }.getOrDefault("") }.lowercase(Locale.ROOT)
    }

    fun matches(query: String, ids: IntArray): Boolean {
        val q = normalize(query)
        if (q.isEmpty()) return true
        return ids.any { id -> normalize(text(id)).contains(q) }
    }

    companion object {
        private fun localized(context: Context, locale: Locale): Resources {
            val config = Configuration(context.resources.configuration)
            config.setLocale(locale)
            return context.createConfigurationContext(config).resources
        }

        /** Lower-case, and fold Arabic ي/ك to Persian ی/ک and drop ZWNJ so either keyboard matches. */
        fun normalize(s: String): String = s.trim().lowercase(Locale.ROOT)
            .replace('ي', 'ی').replace('ك', 'ک').replace("‌", "").replace(" ", " ")
    }
}

/** The current query, bound to an index. */
@Stable
class SettingsQuery(val text: String, private val index: SettingsSearchIndex?) {
    val isEmpty: Boolean get() = text.isBlank()
    fun hit(vararg ids: Int): Boolean = isEmpty || (index?.matches(text, ids) ?: true)
}
