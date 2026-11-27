package com.zeronet.mobile.service

import android.content.Context
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The engine's own diary: what it tried, what answered and why things failed,
 * in plain lines the Diagnostics screen shows. Always on, because "why won't
 * it connect" is asked after the fact; it holds no traffic, addresses of
 * sites visited or config secrets, only server names, protocol families and
 * the errors the core reported.
 *
 * Written by the :vpn process to `filesDir/engine.log` (rotated to `.1` past
 * [MAX_BYTES], so at most twice that on disk) and read by the UI process
 * straight from the file. The core's own log, `zray.log`, sits next to it.
 */
object EngineLog {
    private const val TAG = "ZeroEngine"
    const val FILE = "engine.log"
    const val CORE_FILE = "zray.log"
    private const val MAX_BYTES = 256 * 1024L

    @Volatile private var file: File? = null
    private val time = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue() = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
    }

    fun init(context: Context) {
        file = File(context.filesDir, FILE)
    }

    fun i(message: String) = write('I', message, null)
    fun w(message: String, error: Throwable? = null) = write('W', message, error)
    fun e(message: String, error: Throwable? = null) = write('E', message, error)

    private fun write(level: Char, message: String, error: Throwable?) {
        when (level) {
            'E' -> Log.e(TAG, message, error)
            'W' -> Log.w(TAG, message, error)
            else -> Log.i(TAG, message)
        }
        val target = file ?: return
        val detail = error?.let { " (${it.javaClass.simpleName}: ${it.message})" }.orEmpty()
        val line = "${time.get()!!.format(Date())} $level $message$detail\n"
        synchronized(this) {
            runCatching {
                if (target.length() + line.length > MAX_BYTES) {
                    val old = File(target.parentFile, "$FILE.1")
                    old.delete()
                    target.renameTo(old)
                }
                target.appendText(line)
            }
        }
    }

    /**
     * The last [maxBytes] of a log and its rotated predecessor, oldest first,
     * starting at a line boundary. Safe to call from any process.
     */
    fun tail(dir: File, name: String, maxBytes: Int = 96 * 1024): String {
        val parts = listOf(File(dir, "$name.1"), File(dir, name)).filter { it.isFile }
        val out = StringBuilder()
        var budget = maxBytes.toLong()
        // Newest part first so the budget goes to recent lines.
        val chunks = ArrayList<String>()
        for (part in parts.reversed()) {
            if (budget <= 0) break
            runCatching {
                RandomAccessFile(part, "r").use { raf ->
                    val length = raf.length()
                    val take = minOf(length, budget)
                    raf.seek(length - take)
                    val bytes = ByteArray(take.toInt())
                    raf.readFully(bytes)
                    var text = String(bytes, Charsets.UTF_8)
                    if (take < length) text = text.substringAfter('\n', "")
                    chunks += text
                    budget -= take
                }
            }
        }
        chunks.reversed().forEach { out.append(it) }
        return out.toString()
    }

    /** Empty both logs (and their rotations). */
    fun clear(dir: File) {
        for (name in listOf(FILE, CORE_FILE)) {
            File(dir, "$name.1").delete()
            // Truncate rather than delete: the core keeps its file open.
            runCatching { RandomAccessFile(File(dir, name), "rw").use { it.setLength(0) } }
        }
    }
}
