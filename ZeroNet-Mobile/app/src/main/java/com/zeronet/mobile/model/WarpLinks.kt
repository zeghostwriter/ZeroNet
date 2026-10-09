package com.zeronet.mobile.model

import kotlin.io.encoding.Base64

/**
 * What a `warp://` link says about its account, read without the core.
 *
 * A link is `warp://<base64url of the settings JSON>#remark` (see
 * `zero_config::share_link::warp_link`). The one question the connect ladder
 * asks of it is whether the account runs **WARP inside WARP**: a second
 * WireGuard device (the `inner` block) carried inside the MASQUE tunnel, so
 * the exit is located abroad rather than in the user's own country. Accounts
 * made before that existed have no `inner` block and exit at home.
 */
object WarpLinks {
    private const val SCHEME = "warp://"
    private val urlSafe = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
    private val innerBlock = Regex("\"inner\"\\s*:\\s*\\{")

    /** Whether [link] is a WARP account that runs WARP inside WARP. */
    fun hasInner(link: String): Boolean {
        if (!link.startsWith(SCHEME)) return false
        val body = link.removePrefix(SCHEME).substringBefore('#').trimEnd('=')
        val json = runCatching { urlSafe.decode(body).decodeToString() }.getOrNull() ?: return false
        return innerBlock.containsMatchIn(json)
    }
}
