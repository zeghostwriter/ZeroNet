package com.zeronet.mobile.ui.util

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import com.zeronet.mobile.R
import java.util.Locale

/**
 * Locale-aware number formatting. In Persian every digit is shown in
 * Extended Arabic-Indic form (۰–۹) with the Persian decimal separator, so
 * stats read naturally; the mapping is done here rather than through
 * java.text so it behaves identically on every Android version.
 */
object Num {
    private const val FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹"

    fun isPersian(locale: Locale): Boolean = locale.language == "fa"

    fun localize(ascii: String, locale: Locale): String {
        if (!isPersian(locale)) return ascii
        val out = StringBuilder(ascii.length)
        for (ch in ascii) {
            out.append(
                when (ch) {
                    in '0'..'9' -> FA_DIGITS[ch - '0']
                    '.' -> '٫'
                    ',' -> '٬'
                    '%' -> '٪'
                    else -> ch
                },
            )
        }
        return out.toString()
    }

    fun int(value: Int, locale: Locale): String = localize(value.toString(), locale)
    fun long(value: Long, locale: Locale): String = localize(value.toString(), locale)

    /** Grouped thousands ("12,480"). */
    fun grouped(value: Long, locale: Locale): String = localize(String.format(Locale.US, "%,d", value), locale)

    fun decimal(value: Double, digits: Int, locale: Locale): String =
        localize(String.format(Locale.US, "%.${digits}f", value), locale)
}

@Composable
@ReadOnlyComposable
fun currentLocale(): Locale {
    val locales = LocalConfiguration.current.locales
    return if (locales.isEmpty) Locale.ENGLISH else locales[0]
}

/**
 * Wraps [text] in a left-to-right isolate (LRI…PDI) so addresses and version
 * numbers keep their order inside Persian sentences. Built from code points so
 * no invisible bidi characters live in the source.
 */
fun ltr(text: String): String = LRI + text + PDI

private val LRI = String(Character.toChars(0x2066))
private val PDI = String(Character.toChars(0x2069))

/** A bytes-per-second value with its unit, split so the number can be styled larger. */
data class Rate(val number: String, val unit: String)

fun formatRate(context: Context, bytesPerSecond: Long, locale: Locale): Rate {
    val bits = bytesPerSecond * 8.0
    return when {
        bits >= 1_000_000_000 -> Rate(Num.decimal(bits / 1_000_000_000, 2, locale), context.getString(R.string.unit_gbps))
        bits >= 1_000_000 -> Rate(Num.decimal(bits / 1_000_000, if (bits >= 100_000_000) 0 else 1, locale), context.getString(R.string.unit_mbps))
        bits >= 1_000 -> Rate(Num.decimal(bits / 1_000, 0, locale), context.getString(R.string.unit_kbps))
        else -> Rate(Num.decimal(bits, 0, locale), context.getString(R.string.unit_bps))
    }
}

fun formatBytes(context: Context, bytes: Long, locale: Locale): String {
    val b = bytes.toDouble()
    return when {
        b >= 1e9 -> context.getString(R.string.unit_gb_value, Num.decimal(b / 1e9, 2, locale))
        b >= 1e6 -> context.getString(R.string.unit_mb_value, Num.decimal(b / 1e6, 1, locale))
        b >= 1e3 -> context.getString(R.string.unit_kb_value, Num.decimal(b / 1e3, 0, locale))
        else -> context.getString(R.string.unit_b_value, Num.long(bytes, locale))
    }
}

/** "1:04:09" / "04:09". */
fun formatDuration(millis: Long, locale: Locale): String {
    val total = (millis / 1000).coerceAtLeast(0)
    val h = total / 3600
    val m = (total % 3600) / 60
    val s = total % 60
    val ascii = if (h > 0) String.format(Locale.US, "%d:%02d:%02d", h, m, s) else String.format(Locale.US, "%02d:%02d", m, s)
    return Num.localize(ascii, locale)
}

fun formatDelay(context: Context, ms: Int, locale: Locale): String =
    if (ms < 0) context.getString(R.string.delay_unknown) else context.getString(R.string.delay_ms, Num.int(ms, locale))

/** "just now", "5 min ago", "3 h ago", "2 days ago", "never". */
fun formatAgo(context: Context, at: Long, now: Long, locale: Locale): String {
    if (at <= 0) return context.getString(R.string.ago_never)
    val sec = ((now - at) / 1000).coerceAtLeast(0)
    return when {
        sec < 60 -> context.getString(R.string.ago_now)
        sec < 3600 -> context.getString(R.string.ago_minutes, Num.long(sec / 60, locale))
        sec < 86_400 -> context.getString(R.string.ago_hours, Num.long(sec / 3600, locale))
        else -> context.getString(R.string.ago_days, Num.long(sec / 86_400, locale))
    }
}

/** Composable shorthand for [Num.int] in the current locale. */
@Composable
@ReadOnlyComposable
fun localNum(value: Int): String = Num.int(value, currentLocale())

@Composable
@ReadOnlyComposable
fun appContext(): Context = LocalContext.current
