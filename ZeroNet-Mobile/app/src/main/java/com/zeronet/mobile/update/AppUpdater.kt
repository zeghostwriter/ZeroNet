package com.zeronet.mobile.update

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings as SystemSettings
import android.util.Log
import androidx.core.content.FileProvider
import com.zeronet.mobile.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest

/** A release newer than this build. */
data class ReleaseInfo(
    /** Without the leading "v". */
    val version: String,
    /** The release page, for installing by hand. */
    val page: String,
    /** What changed, one short line each. */
    val notes: List<String>,
    val apkName: String,
    val apkUrl: String,
    val apkSize: Long,
    /** From the release's SHA256SUMS.txt, lowercase hex; null if it has none. */
    val sha256: String?,
)

sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data object UpToDate : UpdateState

    /** The check itself failed. */
    data class CheckFailed(val message: String) : UpdateState
    data class Available(val release: ReleaseInfo) : UpdateState
    data class Downloading(val release: ReleaseInfo, val received: Long, val total: Long) : UpdateState {
        val fraction: Float get() = if (total > 0) (received.toFloat() / total).coerceIn(0f, 1f) else 0f
    }

    /** Downloaded and verified; the system installer takes it from here. */
    data class Ready(val release: ReleaseInfo, val apk: File) : UpdateState

    /**
     * Downloaded, but signed with a different key than the installed app,
     * so Android will not install it over this one.
     */
    data class NeedsReinstall(val release: ReleaseInfo) : UpdateState
    data class Failed(val release: ReleaseInfo, val message: String) : UpdateState
}

/**
 * In-app updates from the GitHub releases. The APK for this phone's CPU is
 * downloaded into the app's cache, checked against the release's
 * SHA256SUMS.txt and the installed app's signing key, and handed to the
 * system installer, which asks the user to confirm.
 *
 * The app is excluded from its own VPN, and GitHub is often filtered on
 * the open network, so while connected every request tries the app's
 * local HTTP proxy (through the tunnel) first.
 */
class AppUpdater private constructor(private val context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val prefs = context.getSharedPreferences("updates", Context.MODE_PRIVATE)
    private val _state = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = _state.asStateFlow()

    /** How to reach the local proxy while connected; null when not. */
    @Volatile var proxyPort: () -> Int? = { null }

    private var job: Job? = null

    /** The version the user chose "Later" on; the automatic check does not offer it again. */
    var dismissedVersion: String?
        get() = prefs.getString(KEY_DISMISSED, null)
        set(value) = prefs.edit().putString(KEY_DISMISSED, value).apply()

    /**
     * The check made at start: at most every [AUTO_CHECK_INTERVAL_MS], and
     * only from published builds.
     */
    fun checkOnStart() {
        if (!BuildConfig.RELEASE_CHANNEL) return
        val last = prefs.getLong(KEY_LAST_CHECK, 0)
        if (System.currentTimeMillis() - last < AUTO_CHECK_INTERVAL_MS) return
        check()
    }

    fun check() {
        when (_state.value) {
            is UpdateState.Checking, is UpdateState.Downloading -> return
            else -> {}
        }
        _state.value = UpdateState.Checking
        job = scope.launch {
            _state.value = runCatching {
                val release = fetchLatest()
                prefs.edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply()
                if (release == null) UpdateState.UpToDate else UpdateState.Available(release)
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                Log.w(TAG, "update check failed", e)
                UpdateState.CheckFailed(e.message ?: "unknown error")
            }
        }
    }

    fun download() {
        val release = when (val s = _state.value) {
            is UpdateState.Available -> s.release
            is UpdateState.Failed -> s.release
            else -> return
        }
        _state.value = UpdateState.Downloading(release, 0, release.apkSize)
        job = scope.launch {
            _state.value = runCatching {
                val apk = downloadApk(release)
                if (signedByUs(apk)) UpdateState.Ready(release, apk) else UpdateState.NeedsReinstall(release)
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                Log.w(TAG, "update download failed", e)
                UpdateState.Failed(release, e.message ?: "unknown error")
            }
        }
    }

    fun cancel() {
        val s = _state.value
        if (s is UpdateState.Downloading) {
            job?.cancel()
            _state.value = UpdateState.Available(s.release)
        }
    }

    /** Whether Android lets this app start package installs (API 26+ asks once). */
    fun canInstall(): Boolean =
        Build.VERSION.SDK_INT < 26 || context.packageManager.canRequestPackageInstalls()

    /** The system screen where the user allows ZeroNet to install apps. */
    fun installPermissionIntent(): Intent =
        Intent(SystemSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))

    /** Open the system installer on the downloaded APK. */
    fun installIntent(): Intent? {
        val ready = _state.value as? UpdateState.Ready ?: return null
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.updates", ready.apk)
        return Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    // ------------------------------------------------------------ network

    private fun fetchLatest(): ReleaseInfo? {
        val json = JSONObject(getText("https://api.github.com/repos/$REPO/releases/latest"))
        val version = json.getString("tag_name").trimStart('v', 'V')
        if (!Versions.isNewer(version, BuildConfig.VERSION_NAME)) return null
        val assets = json.optJSONArray("assets") ?: error("the release has no files")
        val byName = (0 until assets.length()).map { assets.getJSONObject(it) }.associateBy { it.optString("name") }
        val apk = apkCandidates().firstNotNullOfOrNull { byName[it] } ?: error("the release has no Android app")
        val sums = byName["SHA256SUMS.txt"]?.optString("browser_download_url")
            ?.let { runCatching { getText(it) }.getOrNull() }
        return ReleaseInfo(
            version = version,
            page = json.optString("html_url", "https://github.com/$REPO/releases/latest"),
            notes = Versions.releaseNotes(json.optString("body")),
            apkName = apk.getString("name"),
            apkUrl = apk.getString("browser_download_url"),
            apkSize = apk.optLong("size"),
            sha256 = sums?.let { Versions.checksumFor(it, apk.getString("name")) },
        )
    }

    /** The APK for this phone's CPU first, then the one that runs anywhere. */
    private fun apkCandidates(): List<String> {
        val known = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val abi = Build.SUPPORTED_ABIS.firstOrNull { it in known }
        return listOfNotNull(abi?.let { "ZeroNet-Android-$it.apk" }, "ZeroNet-Android-universal.apk")
    }

    private fun routes(): List<Proxy> {
        val port = proxyPort()
        val tunnel = port?.let { Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", it)) }
        return listOfNotNull(tunnel, Proxy.NO_PROXY)
    }

    private fun <T> onAnyRoute(block: (Proxy) -> T): T {
        var last: Throwable? = null
        for (route in routes()) {
            try {
                return block(route)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("no route")
    }

    private fun open(url: String, proxy: Proxy): HttpURLConnection {
        val conn = URL(url).openConnection(proxy) as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "ZeroNet-Android/${BuildConfig.VERSION_NAME}")
        conn.setRequestProperty("Accept-Encoding", "identity")
        when (val code = conn.responseCode) {
            in 200..299 -> {}
            403, 429 -> { conn.disconnect(); error("GitHub is limiting requests; try again in a while") }
            404 -> { conn.disconnect(); error("no release was found") }
            else -> { conn.disconnect(); error("the server answered HTTP $code") }
        }
        return conn
    }

    private fun getText(url: String): String = onAnyRoute { proxy ->
        val conn = open(url, proxy)
        try {
            conn.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun downloadApk(release: ReleaseInfo): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val target = File(dir, "ZeroNet-${release.version}.apk")
        val partial = File(dir, "${target.name}.part")
        val digest = MessageDigest.getInstance("SHA-256")
        val coroutine = kotlin.coroutines.coroutineContext
        onAnyRoute { proxy ->
            digest.reset()
            val conn = open(release.apkUrl, proxy)
            try {
                val total = conn.contentLengthLong.takeIf { it > 0 } ?: release.apkSize
                var received = 0L
                var reported = -1
                conn.inputStream.use { input ->
                    partial.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            coroutine.ensureActive()
                            val n = input.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                            digest.update(buf, 0, n)
                            received += n
                            // One report per 0.5% keeps the UI smooth without flooding it.
                            val step = if (total > 0) (received * 200 / total).toInt() else (received shr 18).toInt()
                            if (step != reported) {
                                reported = step
                                _state.value = UpdateState.Downloading(release, received, total)
                            }
                        }
                    }
                }
                if (total > 0 && received != total) error("the download was cut off before it finished")
            } finally {
                conn.disconnect()
            }
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        if (release.sha256 != null && hash != release.sha256) {
            partial.delete()
            error("the download is damaged (its checksum does not match)")
        }
        if (!partial.renameTo(target)) error("could not save the download")
        return target
    }

    // ------------------------------------------------------------ signatures

    /** Whether [apk] is signed with the same key as the installed app. */
    private fun signedByUs(apk: File): Boolean {
        val pm = context.packageManager
        val installed = signatures(pm.getPackageInfo(context.packageName, signingFlags()))
        val archive = pm.getPackageArchiveInfo(apk.path, signingFlags())?.let(::signatures) ?: return false
        return installed.isNotEmpty() && installed == archive
    }

    @Suppress("DEPRECATION")
    private fun signingFlags(): Int =
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES

    @Suppress("DEPRECATION")
    private fun signatures(info: PackageInfo): Set<String> {
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.let { if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory }
        } else {
            info.signatures
        }
        return sigs.orEmpty().map { it.toCharsString() }.toSet()
    }

    companion object {
        private const val TAG = "AppUpdater"
        const val REPO = "zeghostwriter/ZeroNet"
        private const val KEY_LAST_CHECK = "lastCheck"
        private const val KEY_DISMISSED = "dismissedVersion"
        private const val AUTO_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000L

        @Volatile private var instance: AppUpdater? = null
        fun get(context: Context): AppUpdater =
            instance ?: synchronized(this) { instance ?: AppUpdater(context.applicationContext).also { instance = it } }
    }
}

/** Version comparison and release text, kept free of Android types for unit tests. */
object Versions {
    /** major.minor.patch compared numerically; a pre-release sorts before its release. */
    fun parse(text: String): List<Long>? {
        val t = text.trim().trimStart('v', 'V')
        val cut = t.indexOfFirst { it == '-' || it == '+' }
        val core = if (cut >= 0) t.substring(0, cut) else t
        val pre = cut >= 0 && t[cut] == '-'
        val parts = core.split('.')
        if (parts.isEmpty() || parts.size > 3) return null
        val nums = parts.map { it.toLongOrNull() ?: return null }
        val padded = nums + List(3 - nums.size) { 0L }
        return padded + (if (pre) 0L else 1L)
    }

    fun isNewer(candidate: String, current: String): Boolean {
        val c = parse(candidate) ?: return false
        val cur = parse(current) ?: return false
        for (i in c.indices) if (c[i] != cur[i]) return c[i] > cur[i]
        return false
    }

    /** The bullet points of a release body, without GitHub's "by @someone in <link>". */
    fun releaseNotes(body: String): List<String> = body.lineSequence()
        .map { it.trim() }
        .mapNotNull { line -> line.removePrefix("* ").takeIf { line.startsWith("* ") } ?: line.removePrefix("- ").takeIf { line.startsWith("- ") } }
        .filterNot { it.contains("made their first contribution") }
        .map { item -> item.lastIndexOf(" by @").let { if (it >= 0) item.substring(0, it) else item }.trim() }
        .filter { it.isNotEmpty() }
        .take(6)
        .toList()

    /** A file's hash in a sha256sum listing. */
    fun checksumFor(listing: String, name: String): String? = listing.lineSequence().firstNotNullOfOrNull { line ->
        val parts = line.trim().split(Regex("\\s+"))
        val hash = parts.getOrNull(0) ?: return@firstNotNullOfOrNull null
        val file = parts.getOrNull(1)?.removePrefix("*") ?: return@firstNotNullOfOrNull null
        hash.lowercase().takeIf { file == name && it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
    }
}
