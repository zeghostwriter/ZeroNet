package com.zeronet.mobile.ui.util

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import com.zeronet.mobile.ui.theme.ZeroColors

/**
 * Syntax colouring for a share link, so `vless://…?a=b&c=d#name` reads as its
 * parts rather than one grey run. Mirrors the desktop `linkcolor.rs`.
 *
 * The coloured text is always the exact input, character for character:
 * selecting and copying it must give back a working link, so colour only
 * ever styles the source text and never adds, drops or reorders any of it.
 */
fun highlightLink(uri: String, c: ZeroColors): AnnotatedString = buildAnnotatedString {
    fun push(text: String, color: Color, bold: Boolean = false) {
        if (text.isEmpty()) return
        withStyle(SpanStyle(color = color, fontWeight = if (bold) FontWeight.Bold else null)) { append(text) }
    }

    val schemeAt = uri.indexOf("://")
    if (schemeAt < 0) {
        push(uri, c.text)
        return@buildAnnotatedString
    }
    val schemeEnd = schemeAt + 3
    push(uri.substring(0, schemeEnd), c.accentBright, bold = true)
    val rest = uri.substring(schemeEnd)

    // The fragment (the display name) is free text and may itself contain
    // '?', '&' or '#', so it is split off first.
    val hash = rest.indexOf('#')
    val body = if (hash >= 0) rest.substring(0, hash) else rest
    val fragment = if (hash >= 0) rest.substring(hash + 1) else null
    val q = body.indexOf('?')
    val authority = if (q >= 0) body.substring(0, q) else body
    val query = if (q >= 0) body.substring(q + 1) else null

    // credential@host:port, splitting on the last '@'.
    val at = authority.lastIndexOf('@')
    val hostPort = if (at >= 0) {
        push(authority.substring(0, at), c.warn)
        push("@", c.muted)
        authority.substring(at + 1)
    } else {
        authority
    }
    val close = if (hostPort.startsWith("[")) hostPort.indexOf(']') else -1
    if (close >= 0) {
        // A bracketed IPv6 literal: the port is only the ':digits' after ']'.
        push(hostPort.substring(0, close + 1), c.accentBright)
        val tail = hostPort.substring(close + 1)
        if (tail.startsWith(":")) {
            push(":", c.muted)
            push(tail.substring(1), c.info)
        } else {
            push(tail, c.accentBright)
        }
    } else {
        val colon = hostPort.lastIndexOf(':')
        if (colon >= 0) {
            push(hostPort.substring(0, colon), c.accentBright)
            push(":", c.muted)
            push(hostPort.substring(colon + 1), c.info)
        } else {
            push(hostPort, c.accentBright)
        }
    }

    if (query != null) {
        push("?", c.muted)
        query.split('&').forEachIndexed { index, pair ->
            if (index > 0) push("&", c.muted)
            val eq = pair.indexOf('=')
            if (eq >= 0) {
                push(pair.substring(0, eq), c.accent)
                push("=", c.muted)
                push(pair.substring(eq + 1), c.text)
            } else {
                push(pair, c.accent)
            }
        }
    }
    if (fragment != null) {
        push("#", c.muted)
        push(fragment, c.ok, bold = true)
    }
}
