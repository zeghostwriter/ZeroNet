package com.zeronet.mobile.ui.myserver

import android.content.Context
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.zeronet.mobile.R
import com.zeronet.mobile.client.EngineClient
import com.zeronet.mobile.data.MyServerStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** One DNS record to create at the registrar. */
data class DnsRecord(val kind: String, val name: String, val value: String)

enum class DnsStatus { NotChecked, Checking, Right, Wrong, Unknown }

/** One line of the install progress. */
data class StepView(val step: String, val preset: String?, val done: Boolean)

/** One config to hand to a client: a share link, or files for a client program. */
data class ConfigView(val service: String, val user: String, val link: String?, val files: List<Pair<String, String>>)

/** A service's live figures: counts only, as the server reports them. */
data class InboundUsage(val tag: String, val sessions: Long, val now: Long, val recent: Long, val up: Long, val down: Long)

data class UsageView(val windowSecs: Long, val inbounds: List<InboundUsage>, val at: Long)

/** The screens of the page, in the order a person meets them. */
sealed interface MsScreen {
    data object List : MsScreen
    data object Form : MsScreen
    data object Busy : MsScreen
    data class Identity(val fingerprint: String, val algorithm: String) : MsScreen
    data class Dns(val records: kotlin.collections.List<DnsRecord>, val needsIp: Boolean, val status: DnsStatus) : MsScreen
    data class Progress(val steps: kotlin.collections.List<StepView>, val detail: String, val failed: String?) : MsScreen
    data class Result(val id: String, val notes: kotlin.collections.List<String>) : MsScreen
    data class Server(val id: String) : MsScreen
    data class ConfirmRemove(val id: String) : MsScreen
}

/** The add-a-server form. The password or key lives here only until the install starts. */
@Stable
class MsForm {
    var name by mutableStateOf("")
    var address by mutableStateOf("")
    var port by mutableStateOf("22")
    var user by mutableStateOf("root")
    var password by mutableStateOf("")
    /** Log in with a private key instead of a password (for servers that only allow keys). */
    var useKey by mutableStateOf(false)
    var keyText by mutableStateOf("")
    var passphrase by mutableStateOf("")
    var reality by mutableStateOf(true)
    var xhttp by mutableStateOf(false)
    var masterdns by mutableStateOf(false)
    var domain by mutableStateOf("")
    var error by mutableStateOf<String?>(null)
}

/**
 * State and actions of the "My server" page: set up the person's own server
 * over SSH, see its configs, watch how many devices use it.
 *
 * Everything that touches the server goes through [run], which is
 * [EngineClient.serverCall] in the app (the core's `zero_provision::job`), so
 * this class only decides what to ask next. The password is kept in the form until the install request is built,
 * then cleared; the saved records hold the app's own SSH key and live in
 * [MyServerStore] (private, not backed up).
 */
@Stable
class MyServerModel(
    private val context: Context,
    private val scope: CoroutineScope,
    /** Run one request in the core and stream its events (see [EngineClient.serverCall]). */
    private val run: (JSONObject) -> Flow<JSONObject>,
    /** Add a share link to the app's own server list (so the person can connect to it). */
    private val importLink: suspend (String) -> Boolean,
    private val notify: (String) -> Unit,
    /** Put text on the clipboard; `sensitive` hides it from clipboard previews (links hold keys). */
    val copy: (text: String, sensitive: Boolean) -> Unit = { _, _ -> },
    /** Start a system screen, such as the share sheet. */
    val startIntent: (android.content.Intent) -> Unit = {},
) {
    private val store = MyServerStore.get(context)

    var open by mutableStateOf(false)
    var screen by mutableStateOf<MsScreen>(MsScreen.List)
        private set
    val entries = mutableStateListOf<MyServerStore.Entry>()
    val form = MsForm()
    var bigQr by mutableStateOf(false)
    var shown by mutableStateOf(0)
    val usage = mutableStateMapOf<String, UsageView>()
    val usageError = mutableStateMapOf<String, String>()
    var notice by mutableStateOf<String?>(null)

    private var job: Job? = null
    private var usageJob: Job? = null
    private var pendingAddress = ""

    /** The name server host the DNS plan asked the person to create (`ns.example.com`). */
    private var pendingNsHost = ""

    init {
        scope.launch {
            val saved = withContext(Dispatchers.IO) { store.load() }
            entries.clear()
            entries.addAll(saved)
        }
    }

    fun entry(id: String): MyServerStore.Entry? = entries.firstOrNull { it.id == id }

    // ------------------------------------------------------------ navigation

    /** Open the page. An install still running keeps its progress screen: closing the page never stops it. */
    fun show() {
        open = true
        val running = (screen as? MsScreen.Progress)?.takeIf { it.failed == null }
        if (running == null) screen = MsScreen.List
    }

    /**
     * Close the page. Reading and testing stop, but an install in progress
     * keeps going: cutting it off halfway would leave a half-set-up server.
     */
    fun close() {
        if ((screen as? MsScreen.Progress)?.failed != null || screen !is MsScreen.Progress) job?.cancel()
        usageJob?.cancel()
        open = false
    }

    /** One step back; the first screen closes the page. */
    fun back() {
        when (val s = screen) {
            MsScreen.List -> close()
            MsScreen.Form -> screen = MsScreen.List
            MsScreen.Busy -> { job?.cancel(); screen = MsScreen.Form }
            is MsScreen.Identity, is MsScreen.Dns -> screen = MsScreen.Form
            is MsScreen.Progress -> if (s.failed != null) screen = MsScreen.Form else close()
            is MsScreen.Result -> openServer(s.id)
            is MsScreen.Server -> if (bigQr) bigQr = false else { usageJob?.cancel(); screen = MsScreen.List }
            is MsScreen.ConfirmRemove -> screen = MsScreen.Server(s.id)
        }
    }

    fun startAdd() {
        form.password = ""
        form.keyText = ""
        form.passphrase = ""
        form.error = null
        if (form.name.isBlank()) form.name = context.getString(R.string.ms_default_name)
        screen = MsScreen.Form
    }

    fun openServer(id: String) {
        notice = null
        shown = 0
        bigQr = false
        screen = MsScreen.Server(id)
    }

    // ---------------------------------------------------------------- the form

    /** Check the form and look at the server's identity; no secret is sent. */
    fun submit() {
        val problem = validate()
        if (problem != null) {
            form.error = problem
            return
        }
        form.error = null
        pendingAddress = form.address.trim()
        screen = MsScreen.Busy
        job?.cancel()
        job = scope.launch {
            val done = call(JSONObject().put("op", "fingerprint").put("host", pendingAddress).put("port", form.port.trim().toInt()))
            if (screen != MsScreen.Busy) return@launch
            if (done.optBoolean("ok")) {
                screen = MsScreen.Identity(done.optString("fingerprint"), done.optString("algorithm"))
            } else {
                form.error = done.optString("error")
                screen = MsScreen.Form
            }
        }
    }

    private fun validate(): String? {
        val address = form.address.trim()
        if (address.isEmpty()) return context.getString(R.string.ms_err_address)
        if (address.any { it.isWhitespace() } || address.contains("://")) return context.getString(R.string.ms_err_address_shape)
        if (form.port.trim().toIntOrNull()?.let { it in 1..65535 } != true) return context.getString(R.string.ms_err_port)
        if (form.user.isBlank()) return context.getString(R.string.ms_err_user)
        if (form.useKey) {
            if (form.keyText.isBlank()) return context.getString(R.string.ms_err_key)
            if (!looksLikePrivateKey(form.keyText)) return context.getString(R.string.ms_err_key_shape)
        } else if (form.password.isEmpty()) {
            return context.getString(R.string.ms_err_password)
        }
        if (!form.reality && !form.xhttp && !form.masterdns) return context.getString(R.string.ms_err_choose)
        if (form.masterdns && form.domain.isBlank()) return context.getString(R.string.ms_err_domain)
        return null
    }

    /** The person confirmed the fingerprint: MasterDNS needs its domain set up first. */
    fun trustIdentity() {
        val identity = screen as? MsScreen.Identity ?: return
        pendingFingerprint = identity.fingerprint
        pendingAlgorithm = identity.algorithm
        if (!form.masterdns) {
            install(identity)
            return
        }
        screen = MsScreen.Busy
        job?.cancel()
        job = scope.launch {
            val done = call(JSONObject().put("op", "dns_plan").put("domain", form.domain).put("server", pendingAddress))
            if (screen != MsScreen.Busy) return@launch
            if (done.optBoolean("ok")) {
                val records = done.optJSONArray("records").objects().map {
                    DnsRecord(it.optString("kind"), it.optString("name"), it.optString("value"))
                }
                form.domain = done.optString("domain")
                pendingNsHost = done.optString("ns_host")
                screen = MsScreen.Dns(records, done.optBoolean("needs_ip"), DnsStatus.NotChecked)
            } else {
                form.error = done.optString("error")
                screen = MsScreen.Form
            }
        }
    }

    fun checkDns() {
        val dns = screen as? MsScreen.Dns ?: return
        screen = dns.copy(status = DnsStatus.Checking)
        scope.launch {
            val done = call(JSONObject().put("op", "dns").put("ns_host", pendingNsHost).put("server", pendingAddress))
            val now = screen as? MsScreen.Dns ?: return@launch
            val status = when (done.optString("status")) {
                "right" -> DnsStatus.Right
                "wrong" -> DnsStatus.Wrong
                else -> DnsStatus.Unknown
            }
            screen = now.copy(status = status)
        }
    }

    /** Start installing. The password leaves the form here. */
    fun install(identity: MsScreen.Identity? = null) {
        val fingerprint = identity?.fingerprint ?: (screen as? MsScreen.Identity)?.fingerprint ?: pendingFingerprint ?: return
        val algorithm = identity?.algorithm ?: (screen as? MsScreen.Identity)?.algorithm ?: pendingAlgorithm.orEmpty()
        pendingFingerprint = fingerprint
        pendingAlgorithm = algorithm
        val request = JSONObject()
            .put("op", "install")
            .put("host", pendingAddress)
            .put("port", form.port.trim().toInt())
            .put("user", form.user.trim())
            .put("trust", JSONObject().put("fingerprint", fingerprint).put("algorithm", algorithm))
            .put("name", form.name.trim().ifEmpty { context.getString(R.string.ms_default_name) })
            .put("reality", form.reality)
            .put("xhttp", form.xhttp)
        if (form.masterdns) request.put("masterdns_domain", form.domain.trim())
        if (form.useKey) {
            request.put("private_key", form.keyText.trim())
            if (form.passphrase.isNotEmpty()) request.put("key_passphrase", form.passphrase)
        } else {
            request.put("password", form.password)
        }
        form.password = ""
        form.keyText = ""
        form.passphrase = ""
        var progress = MsScreen.Progress(emptyList(), "", null)
        screen = progress
        job?.cancel()
        job = scope.launch {
            try {
                run(request).collect { e ->
                    when (e.optString("t")) {
                        "step" -> {
                            val steps = progress.steps.map { it.copy(done = true) } +
                                StepView(e.optString("step"), e.optString("preset").takeIf { it.isNotEmpty() && it != "null" }, false)
                            progress = progress.copy(steps = steps)
                            screen = progress
                        }
                        "detail" -> {
                            progress = progress.copy(detail = e.optString("text"))
                            screen = progress
                        }
                        "done" -> if (e.optBoolean("ok")) finishInstall(e) else {
                            screen = progress.copy(failed = e.optString("error"))
                        }
                    }
                }
            } catch (c: CancellationException) {
                throw c
            }
        }
    }

    private var pendingFingerprint: String? = null
    private var pendingAlgorithm: String? = null

    private suspend fun finishInstall(done: JSONObject) {
        val record = done.getJSONObject("record")
        val configs = done.optJSONArray("configs") ?: JSONArray()
        val entry = MyServerStore.Entry(record, configs)
        withContext(Dispatchers.IO) { store.put(entry) }
        entries.removeAll { it.id == entry.id }
        entries.add(entry)
        val notes = done.optJSONArray("notes").objects().map { noteText(it) }
        shown = 0
        bigQr = false
        pendingFingerprint = null
        screen = MsScreen.Result(entry.id, notes)
    }

    /** A note from the installer, as a sentence. */
    private fun noteText(note: JSONObject): String = when (note.optString("kind")) {
        "port_moved" -> context.getString(R.string.ms_note_port_moved, note.optInt("wanted"), note.optString("held_by"), note.optInt("used"))
        "firewall_opened" -> context.getString(R.string.ms_note_firewall_opened, note.optString("which"))
        "provider_firewall" -> {
            val ports = listOfNotNull(
                note.optJSONArray("tcp")?.takeIf { it.length() > 0 }?.let { "TCP " + it.ints().joinToString(", ") },
                note.optJSONArray("udp")?.takeIf { it.length() > 0 }?.let { "UDP " + it.ints().joinToString(", ") },
            )
            context.getString(R.string.ms_note_provider_firewall, ports.joinToString(" / "))
        }
        "unverified" -> context.getString(R.string.ms_note_unverified)
        "key_not_working" -> context.getString(R.string.ms_note_key)
        else -> ""
    }

    // ------------------------------------------------------------- one server

    fun configs(id: String): List<ConfigView> = entry(id)?.configs.objects().map { c ->
        ConfigView(
            service = c.optString("service"),
            user = c.optString("user"),
            link = c.optString("link").takeIf { it.isNotEmpty() && it != "null" },
            files = c.optJSONArray("files").objects().map { it.optString("name") to it.optString("text") },
        )
    }

    /** Read the live figures now, and every few seconds while the server page stays open. */
    fun watchUsage(id: String) {
        usageJob?.cancel()
        usageJob = scope.launch {
            while (screen == MsScreen.Server(id)) {
                refreshUsage(id)
                kotlinx.coroutines.delay(POLL_MS)
            }
        }
    }

    fun stopWatching() {
        usageJob?.cancel()
    }

    suspend fun refreshUsage(id: String) {
        val entry = entry(id) ?: return
        val done = call(JSONObject().put("op", "usage").put("record", entry.record))
        if (done.optBoolean("ok")) {
            val u = done.getJSONObject("usage")
            usageError.remove(id)
            usage[id] = UsageView(
                u.optLong("window_secs"),
                u.optJSONArray("inbounds").objects().map {
                    InboundUsage(
                        it.optString("tag"), it.optLong("sessions"), it.optLong("devices_now"),
                        it.optLong("devices_recent"), it.optLong("uplink"), it.optLong("downlink"),
                    )
                },
                System.currentTimeMillis(),
            )
        } else if (done.optString("error") != "cancelled") {
            usageError[id] = done.optString("error")
        }
    }

    /** Add the server's share link to the app's own list, so the person can connect to it. */
    fun useInApp(id: String) {
        // The config on screen, else the first one that has a link.
        val all = configs(id)
        val link = all.getOrNull(shown)?.link ?: all.firstNotNullOfOrNull { it.link } ?: return
        scope.launch {
            notify(context.getString(if (importLink(link)) R.string.ms_used_in_app else R.string.ms_use_failed))
        }
    }

    fun probe(id: String) {
        val entry = entry(id) ?: return
        notice = context.getString(R.string.ms_testing)
        scope.launch {
            val done = call(JSONObject().put("op", "probe").put("record", entry.record))
            notice = when {
                !done.optBoolean("ok") -> done.optString("error")
                done.optInt("answered") == 0 -> context.getString(R.string.ms_probe_none)
                else -> context.getString(R.string.ms_probe_ok, done.optInt("answered"), done.optInt("of"), done.optInt("best_ms"))
            }
        }
    }

    fun askRemove(id: String) {
        screen = MsScreen.ConfirmRemove(id)
    }

    fun remove(id: String) {
        val entry = entry(id) ?: return
        usageJob?.cancel()
        screen = MsScreen.Busy
        job?.cancel()
        job = scope.launch {
            val done = call(JSONObject().put("op", "remove").put("record", entry.record))
            if (done.optBoolean("ok")) {
                withContext(Dispatchers.IO) { store.remove(id) }
                entries.removeAll { it.id == id }
                usage.remove(id)
                usageError.remove(id)
                notice = context.getString(R.string.ms_removed)
                screen = MsScreen.List
            } else {
                notice = done.optString("error")
                screen = MsScreen.Server(id)
            }
        }
    }

    /** Drop the saved record without touching the server (it is unreachable or already gone). */
    fun forget(id: String) {
        scope.launch {
            withContext(Dispatchers.IO) { store.remove(id) }
            entries.removeAll { it.id == id }
            usage.remove(id)
            usageError.remove(id)
            screen = MsScreen.List
        }
    }

    // ------------------------------------------------------------------ plumbing

    /** Run one request and return its `done` event. */
    private suspend fun call(request: JSONObject): JSONObject {
        var last = JSONObject().put("t", "done").put("ok", false).put("error", "cancelled")
        run(request).collect { e -> if (e.optString("t") == "done") last = e }
        return last
    }

    companion object {
        private const val POLL_MS = 5_000L
    }
}

private fun JSONArray?.objects(): List<JSONObject> =
    if (this == null) emptyList() else List(length()) { getJSONObject(it) }

private fun JSONArray.ints(): List<Int> = List(length()) { getInt(it) }

/** Whether pasted text is a private key (OpenSSH, PEM or PuTTY), not a public key or something else. */
internal fun looksLikePrivateKey(text: String): Boolean =
    text.contains("PRIVATE KEY") || text.contains("PuTTY-User-Key-File")
