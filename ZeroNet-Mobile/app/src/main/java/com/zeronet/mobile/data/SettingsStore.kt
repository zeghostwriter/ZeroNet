package com.zeronet.mobile.data

import android.content.Context
import com.zeronet.mobile.model.Settings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.io.File

/**
 * The user's preferences, owned by the UI process.
 *
 * Stored as one JSON document (atomic write via rename) rather than
 * SharedPreferences: it is read once at start into an immutable [Settings],
 * every change is a single `update { copy(...) }`, and the same file is what
 * the :vpn process reads for the quick-settings tile and boot auto-connect —
 * so there is exactly one source of truth and no cross-process prefs.
 */
class SettingsStore private constructor(context: Context) {
    private val file = File(context.filesDir, FILE_NAME)
    private val _settings = MutableStateFlow(load(file))
    val settings: StateFlow<Settings> = _settings.asStateFlow()

    val current: Settings get() = _settings.value

    @Synchronized
    fun update(transform: (Settings) -> Settings) {
        val next = transform(_settings.value)
        if (next == _settings.value) return
        _settings.value = next
        write(file, next)
    }

    companion object {
        const val FILE_NAME = "settings.json"

        @Volatile private var instance: SettingsStore? = null
        fun get(context: Context): SettingsStore =
            instance ?: synchronized(this) { instance ?: SettingsStore(context.applicationContext).also { instance = it } }

        /** Read-only snapshot for the :vpn process (tile, boot receiver). */
        fun readSnapshot(context: Context): Settings = load(File(context.filesDir, FILE_NAME))

        private fun load(file: File): Settings = runCatching {
            if (file.exists()) Settings.fromJson(JSONObject(file.readText())) else Settings()
        }.getOrDefault(Settings())

        private fun write(file: File, settings: Settings) {
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(settings.toJson().toString())
            if (!tmp.renameTo(file)) {
                file.writeText(settings.toJson().toString())
                tmp.delete()
            }
        }
    }
}
