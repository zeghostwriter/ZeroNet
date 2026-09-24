package com.zeronet.mobile.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import com.zeronet.mobile.R

/**
 * Vazirmatn (variable, OFL-1.1) for both scripts: it carries a full Latin
 * set drawn to sit with the Persian, so mixed text ("Germany · ۱۴۰ ms") keeps
 * one rhythm. Each weight is a named instance of the same file selected via
 * the `wght` axis.
 */
private fun vazir(weight: Int) = Font(
    resId = R.font.vazirmatn,
    weight = FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight)),
)

val Vazirmatn: FontFamily = FontFamily(
    vazir(300), vazir(400), vazir(500), vazir(600), vazir(700), vazir(800),
)

private val Trim = LineHeightStyle(
    alignment = LineHeightStyle.Alignment.Center,
    trim = LineHeightStyle.Trim.None,
)

private fun style(size: Int, line: Int, weight: Int, tracking: Double = 0.0) = TextStyle(
    fontFamily = Vazirmatn,
    fontWeight = FontWeight(weight),
    fontSize = size.sp,
    lineHeight = line.sp,
    letterSpacing = tracking.em,
    lineHeightStyle = Trim,
)

/**
 * Persian script is cursive: letter-spacing breaks the joins, so the scale
 * carries no tracking. Latin-only labels that want tracking (the orb's
 * CONNECT) apply it themselves through [latinTracking].
 */
val ZeroTypography = Typography(
    displayLarge = style(52, 60, 700),
    displayMedium = style(40, 48, 700),
    displaySmall = style(32, 40, 700),
    headlineLarge = style(30, 38, 700),
    headlineMedium = style(26, 34, 700),
    headlineSmall = style(22, 30, 700),
    titleLarge = style(20, 28, 700),
    titleMedium = style(16, 24, 600),
    titleSmall = style(14, 20, 600),
    bodyLarge = style(16, 26, 400),
    bodyMedium = style(14, 22, 400),
    bodySmall = style(12, 18, 400),
    labelLarge = style(14, 20, 600),
    labelMedium = style(12, 16, 600),
    labelSmall = style(11, 16, 600),
)
