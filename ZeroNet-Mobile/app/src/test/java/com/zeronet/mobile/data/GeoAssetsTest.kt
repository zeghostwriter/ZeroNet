package com.zeronet.mobile.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class GeoAssetsTest {
    private val context = RuntimeEnvironment.getApplication()

    private fun bundled(name: String) = context.assets.open("geo/$name").use { it.readBytes() }

    @Test
    fun `the bundled rule sets land where the core reads them`() {
        val dir = GeoAssets.directory(context)
        dir.deleteRecursively()
        assertNull(GeoAssets.install(context))
        for (name in listOf("geosite.dat", "geoip.dat")) {
            val installed = File(dir, name)
            assertTrue("$name missing", installed.isFile)
            assertArrayEquals(bundled(name), installed.readBytes())
        }
        // The core reads <dataDir>/assets, and the app passes filesDir as dataDir.
        assertTrue(dir == File(context.filesDir, "assets"))
    }

    @Test
    fun `a damaged copy is replaced and stale download bookkeeping dropped`() {
        val dir = GeoAssets.directory(context)
        assertNull(GeoAssets.install(context))
        File(dir, "geoip.dat").writeBytes(byteArrayOf(1, 2, 3))
        File(dir, "geoip.dat.meta").writeText("source=https://example.invalid\n")
        assertNull(GeoAssets.install(context))
        assertArrayEquals(bundled("geoip.dat"), File(dir, "geoip.dat").readBytes())
        assertFalse(File(dir, "geoip.dat.meta").exists())
        // No temporary files left behind.
        assertTrue(dir.listFiles().orEmpty().none { it.name.endsWith(".tmp") })
    }
}
