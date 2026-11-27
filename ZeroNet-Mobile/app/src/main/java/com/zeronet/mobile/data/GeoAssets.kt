package com.zeronet.mobile.data

import android.content.Context
import java.io.File

/**
 * The routing rule sets the core reads from `filesDir/assets`: geosite.dat and
 * geoip.dat, trimmed to the tags the app's rules use (Iran-direct, ad
 * blocking, private ranges; see `ZeroNet-Mobile/tools/trim-geodata.py`) and shipped in the
 * APK under `assets/geo/`.
 *
 * Nothing used to put them there, so every geosite:/geoip: rule was skipped.
 * Shipping them means the rules work from the first launch, offline, with no
 * download over a filtered, metered network; they update with the app.
 */
object GeoAssets {
    private val FILES = listOf("geosite.dat", "geoip.dat")

    /** Where the core looks: the `assets` directory under the data dir it was given. */
    fun directory(context: Context): File = File(context.filesDir, "assets")

    /**
     * Copy each bundled file in unless the installed copy is already the
     * same. Written to a temporary file and renamed, so the core (or the other
     * app process doing the same) never reads a half-written file.
     * Returns a problem to log, or null.
     */
    fun install(context: Context): String? {
        val dir = directory(context)
        if (!dir.isDirectory && !dir.mkdirs()) return "cannot create ${dir.path}"
        for (name in FILES) {
            val bundled = runCatching { context.assets.open("geo/$name").use { it.readBytes() } }
                .getOrElse { return "bundled $name is missing: ${it.message}" }
            val target = File(dir, name)
            if (target.isFile && target.length() == bundled.size.toLong() && target.readBytes().contentEquals(bundled)) continue
            val temp = File(dir, "$name.${android.os.Process.myPid()}.tmp")
            val written = runCatching {
                temp.writeBytes(bundled)
                if (!temp.renameTo(target)) error("rename failed")
            }
            if (written.isFailure) {
                temp.delete()
                return "cannot install $name: ${written.exceptionOrNull()?.message}"
            }
            // Download bookkeeping from an earlier fallback fetch no longer
            // describes this file.
            File(dir, "$name.meta").delete()
        }
        return null
    }
}
