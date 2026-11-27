package com.zeronet.mobile.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VersionsTest {
    @Test
    fun versionsCompareNumerically() {
        assertTrue(Versions.isNewer("v0.1.10", "0.1.9"))
        assertTrue(Versions.isNewer("0.2.0", "0.1.99"))
        assertTrue(Versions.isNewer("1.0.0", "1.0.0-beta"))
        assertFalse(Versions.isNewer("1.0.0-beta", "1.0.0"))
        assertFalse(Versions.isNewer("v0.1.4", "0.1.4"))
        assertFalse(Versions.isNewer("0.1.3", "0.1.4"))
        assertFalse(Versions.isNewer("nightly", "0.1.4"))
        assertTrue(Versions.isNewer("0.2", "0.1.4"))
    }

    @Test
    fun releaseNotesKeepTheChangesOnly() {
        val body = """
            ## Download
            | | |
            |---|---|
            | Windows | `x.zip` |

            ## What's Changed
            * Server tests: survive forged DNS by @someone in https://github.com/x/y/pull/10
            * README: fix layout by @someone in https://github.com/x/y/pull/11

            ## New Contributors
            * @a made their first contribution in https://github.com/x/y/pull/1
        """.trimIndent()
        assertEquals(listOf("Server tests: survive forged DNS", "README: fix layout"), Versions.releaseNotes(body))
    }

    @Test
    fun checksumsAreFoundByFileName() {
        val a = "a".repeat(64)
        val b = "B".repeat(64)
        val listing = "$a  ZeroNet-Android-universal.apk\n$b *ZeroNet-Android-arm64-v8a.apk\n"
        assertEquals(a, Versions.checksumFor(listing, "ZeroNet-Android-universal.apk"))
        assertEquals("b".repeat(64), Versions.checksumFor(listing, "ZeroNet-Android-arm64-v8a.apk"))
        assertNull(Versions.checksumFor(listing, "ZeroNet-Android-x86_64.apk"))
        assertNull(Versions.checksumFor("short  x.apk", "x.apk"))
    }
}
