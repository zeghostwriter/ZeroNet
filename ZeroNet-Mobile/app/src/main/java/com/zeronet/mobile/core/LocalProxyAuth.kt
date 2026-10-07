package com.zeronet.mobile.core

import android.content.Context
import java.io.File
import java.net.Authenticator
import java.net.PasswordAuthentication
import java.security.SecureRandom

/**
 * The password on the app's own local proxy.
 *
 * In VPN mode other apps reach the tunnel through the VPN interface, and the
 * local HTTP port serves only this app's own checks and downloads. Left open
 * it would also serve every other app on the phone: any of them could connect
 * to it, ask a what-is-my-address service through it, and learn the address of
 * the server the user is hiding behind. So the core is given a password for
 * that port (see `local_auth` in the config request), and this object answers
 * with it when one of the app's own requests is asked for it.
 *
 * The password is made once per install and kept in the app's private files,
 * because the UI process and the VPN process both use the proxy and have to
 * agree on it. No other app can read it there.
 */
object LocalProxyAuth {
    private const val FILE = "local-proxy-auth"

    @Volatile
    private var pair: Pair<String, String>? = null

    val user: String get() = pair?.first.orEmpty()
    val pass: String get() = pair?.second.orEmpty()

    /** `user:pass`, the form the native side takes; empty before [init]. */
    val userPass: String get() = pair?.let { "${it.first}:${it.second}" }.orEmpty()

    /** Load the password, making it on first run, and start answering with it. */
    fun init(context: Context) {
        val loaded = runCatching { loadOrCreate(File(context.filesDir, FILE)) }.getOrNull() ?: return
        pair = loaded
        Authenticator.setDefault(object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication? {
                // Only for our own loopback proxy: a password is never handed
                // to a server, or to any proxy somewhere else.
                val local = requestorType == RequestorType.PROXY &&
                    (requestingSite?.isLoopbackAddress == true || requestingHost == "127.0.0.1")
                return if (local) PasswordAuthentication(loaded.first, loaded.second.toCharArray()) else null
            }
        })
    }

    private fun loadOrCreate(file: File): Pair<String, String>? {
        read(file)?.let { return it }
        val random = SecureRandom()
        val fresh = token(random, 8) + "\n" + token(random, 24)
        // Written beside the target and moved into place, so the other
        // process never reads half a file; whichever got there first wins.
        val temp = File(file.parentFile, "$FILE.${android.os.Process.myPid()}.tmp")
        temp.writeText(fresh)
        if (file.exists() || !temp.renameTo(file)) temp.delete()
        return read(file)
    }

    private fun read(file: File): Pair<String, String>? {
        if (!file.isFile) return null
        val lines = file.readLines()
        return if (lines.size >= 2 && lines[0].isNotEmpty() && lines[1].isNotEmpty()) lines[0] to lines[1] else null
    }

    /** Letters and digits only: nothing a header or a JSON string needs escaped. */
    private fun token(random: SecureRandom, length: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return buildString(length) { repeat(length) { append(alphabet[random.nextInt(alphabet.length)]) } }
    }
}
