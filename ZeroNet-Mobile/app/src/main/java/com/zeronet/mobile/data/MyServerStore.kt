package com.zeronet.mobile.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * The servers the person set up from the "My server" page.
 *
 * A record holds the app's own SSH key for the server, so it can open that
 * server: the file lives in the app's no-backup directory (private to this
 * app, never copied into a backup or to another device) and is replaced
 * atomically so a crash mid-write cannot lose the list. The engine process
 * never reads it; the UI hands a record to a request and gets one back.
 *
 * Each entry keeps the record as the core wrote it (opaque here) plus the
 * client configs derived from it, so the page can show links and QR codes
 * without asking the engine again.
 */
class MyServerStore private constructor(context: Context) {

    private val file = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    /** One saved server. */
    data class Entry(val record: JSONObject, val configs: JSONArray) {
        val id: String get() = record.optString("id")
        val name: String get() = record.optString("name")
        val host: String get() = record.optString("host")

        /** The services installed, as the core's `kind` words (`reality`, `master_dns`). */
        val kinds: List<String>
            get() = record.optJSONArray("services")?.let { a -> List(a.length()) { a.getJSONObject(it).optString("kind") } }.orEmpty()

        /** The inbound tag each service reports its usage under. */
        fun tagOf(kind: String): String =
            if (kind == "master_dns") "masterdns" else record.optJSONArray("services")?.let { a ->
                (0 until a.length()).map { a.getJSONObject(it) }.firstOrNull { it.optString("kind") == kind }?.optString("tag")
            } ?: kind
    }

    @Synchronized
    fun load(): List<Entry> {
        val text = runCatching { file.readText() }.getOrNull() ?: return emptyList()
        // A damaged or unreadable file is an empty list, not a crash.
        val array = runCatching { JSONArray(text) }.getOrNull() ?: return emptyList()
        return (0 until array.length()).mapNotNull { i ->
            runCatching {
                val o = array.getJSONObject(i)
                Entry(o.getJSONObject("record"), o.optJSONArray("configs") ?: JSONArray())
            }.getOrNull()
        }
    }

    /** Add [entry], replacing an older one with the same id. */
    @Synchronized
    fun put(entry: Entry) = save(load().filter { it.id != entry.id } + entry)

    @Synchronized
    fun remove(id: String) = save(load().filter { it.id != id })

    private fun save(entries: List<Entry>) {
        val array = JSONArray()
        entries.forEach { array.put(JSONObject().put("record", it.record).put("configs", it.configs)) }
        val temp = File(file.parentFile, "$FILE_NAME.tmp")
        temp.writeText(array.toString())
        if (!temp.renameTo(file)) {
            file.delete()
            temp.renameTo(file)
        }
    }

    companion object {
        private const val FILE_NAME = "my-servers.json"

        @Volatile private var instance: MyServerStore? = null
        fun get(context: Context): MyServerStore =
            instance ?: synchronized(this) { instance ?: MyServerStore(context).also { instance = it } }
    }
}
