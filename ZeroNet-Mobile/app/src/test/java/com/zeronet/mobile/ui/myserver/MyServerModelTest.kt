package com.zeronet.mobile.ui.myserver

import com.zeronet.mobile.data.MyServerStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

/**
 * The page's state machine against a scripted core: every request the page
 * makes is recorded and answered with the events the real job would send
 * (see zero_provision::job), so no network and no server are involved.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class MyServerModelTest {
    private val context = RuntimeEnvironment.getApplication()
    private val requests = mutableListOf<JSONObject>()
    private val answers = mutableMapOf<String, List<JSONObject>>()
    private val notices = mutableListOf<String>()

    @Before
    fun freshStore() {
        MyServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        File(context.noBackupFilesDir, "my-servers.json").delete()
        requests.clear()
        answers.clear()
        notices.clear()
    }

    private fun model(): MyServerModel = MyServerModel(
        context = context,
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
        run = ::core,
        importLink = { true },
        notify = { notices += it },
    )

    private fun core(request: JSONObject): Flow<JSONObject> = flow {
        requests += request
        answers[request.getString("op")].orEmpty().forEach { emit(it) }
    }

    private fun done(vararg fields: Pair<String, Any>) =
        JSONObject().put("t", "done").put("ok", true).also { o -> fields.forEach { o.put(it.first, it.second) } }

    private fun fail(text: String) = JSONObject().put("t", "done").put("ok", false).put("error", text)

    /** A record as the core writes it, small enough to read. */
    private fun record(id: String = "srv1") = JSONObject()
        .put("id", id).put("name", "Mine").put("host", "203.0.113.7")
        .put("services", JSONArray().put(JSONObject().put("kind", "reality").put("tag", "reality-in")))

    private fun fill(m: MyServerModel, masterdns: Boolean = false) {
        m.startAdd()
        m.form.address = "203.0.113.7"
        m.form.password = "hunter2"
        m.form.masterdns = masterdns
        if (masterdns) m.form.domain = "t.example.com"
    }

    private fun waitFor(what: String, check: () -> Boolean) {
        val end = System.currentTimeMillis() + 5_000
        while (!check()) {
            check(System.currentTimeMillis() < end) { "timed out waiting for $what" }
            Thread.sleep(10)
        }
    }

    @Test
    fun `a form with a missing field says which one and sends nothing`() {
        val m = model()
        m.startAdd()
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_address), m.form.error)
        m.form.address = "https://203.0.113.7"
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_address_shape), m.form.error)
        m.form.address = "203.0.113.7"
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_password), m.form.error)
        assertTrue(requests.isEmpty())
        assertEquals(MsScreen.Form, m.screen)
    }

    @Test
    fun `the first request carries no password and shows the server's fingerprint`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        val m = model()
        fill(m)
        m.submit()
        assertEquals("fingerprint", requests.single().getString("op"))
        assertFalse(requests.single().has("password"))
        assertEquals(MsScreen.Identity("SHA256:abc", "ssh-ed25519"), m.screen)
    }

    @Test
    fun `an unreachable server returns to the form with the core's sentence`() {
        answers["fingerprint"] = listOf(fail("Nothing answered at 203.0.113.7:22."))
        val m = model()
        fill(m)
        m.submit()
        assertEquals(MsScreen.Form, m.screen)
        assertEquals("Nothing answered at 203.0.113.7:22.", m.form.error)
    }

    @Test
    fun `confirming the fingerprint installs with that fingerprint and then forgets the password`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        answers["install"] = listOf(
            JSONObject().put("t", "step").put("step", "download").put("preset", "reality").put("number", 3).put("of", 8),
            JSONObject().put("t", "detail").put("text", "Downloading"),
            done(
                "record" to record(),
                "configs" to JSONArray().put(JSONObject().put("service", "reality").put("user", "Main").put("link", "vless://x@h:443").put("files", JSONArray())),
                "notes" to JSONArray().put(JSONObject().put("kind", "unverified")),
            ),
        )
        val m = model()
        fill(m)
        m.submit()
        m.trustIdentity()
        waitFor("the result") { m.screen is MsScreen.Result }
        val install = requests.single { it.getString("op") == "install" }
        assertEquals("hunter2", install.getString("password"))
        assertEquals("SHA256:abc", install.getJSONObject("trust").getString("fingerprint"))
        assertEquals("", m.form.password)
        assertEquals(listOf("srv1"), m.entries.map { it.id })
        assertEquals("vless://x@h:443", m.configs("srv1").single().link)
        assertEquals(1, (m.screen as MsScreen.Result).notes.size)
        // The record survives a restart of the app.
        assertEquals(listOf("srv1"), MyServerStore.get(context).load().map { it.id })
    }

    @Test
    fun `logging in with a key sends the key and passphrase instead of a password, then forgets them`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        answers["install"] = listOf(done("record" to record(), "configs" to JSONArray(), "notes" to JSONArray()))
        val m = model()
        m.startAdd()
        m.form.address = "203.0.113.7"
        m.form.useKey = true
        m.form.keyText = "  -----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
        m.form.passphrase = "open sesame"
        m.submit()
        m.trustIdentity()
        waitFor("the result") { m.screen is MsScreen.Result }
        // Looking at the identity sends no secret of any kind.
        val first = requests.first { it.getString("op") == "fingerprint" }
        assertFalse(first.has("private_key") || first.has("password"))
        val install = requests.single { it.getString("op") == "install" }
        assertTrue(install.getString("private_key").startsWith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        assertEquals("open sesame", install.getString("key_passphrase"))
        assertFalse(install.has("password"))
        assertEquals("", m.form.keyText)
        assertEquals("", m.form.passphrase)
    }

    @Test
    fun `a key form says what is wrong before anything is sent`() {
        val m = model()
        m.startAdd()
        m.form.address = "203.0.113.7"
        m.form.useKey = true
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_key), m.form.error)
        // A public key is the usual mistake.
        m.form.keyText = "ssh-ed25519 AAAAC3Nza user@host"
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_key_shape), m.form.error)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `the xhttp choice reaches the install request and counts as something to install`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        answers["install"] = listOf(fail("stop here"))
        val m = model()
        fill(m)
        m.form.reality = false
        m.submit()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_choose), m.form.error)
        m.form.xhttp = true
        m.submit()
        m.trustIdentity()
        waitFor("the install request") { requests.any { it.getString("op") == "install" } }
        val install = requests.single { it.getString("op") == "install" }
        assertTrue(install.getBoolean("xhttp"))
        assertFalse(install.getBoolean("reality"))
    }

    @Test
    fun `an install that fails shows the sentence and keeps no server`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        answers["install"] = listOf(fail("Login failed. Check the password."))
        val m = model()
        fill(m)
        m.submit()
        m.trustIdentity()
        waitFor("the failure") { (m.screen as? MsScreen.Progress)?.failed != null }
        assertEquals("Login failed. Check the password.", (m.screen as MsScreen.Progress).failed)
        assertTrue(m.entries.isEmpty())
        assertTrue(MyServerStore.get(context).load().isEmpty())
        m.back()
        assertEquals(MsScreen.Form, m.screen)
    }

    @Test
    fun `masterdns asks for the dns records first and checks the name server the plan named`() {
        answers["fingerprint"] = listOf(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
        answers["dns_plan"] = listOf(
            done(
                "domain" to "t.example.com",
                "ns_host" to "ns.example.com",
                "needs_ip" to false,
                "records" to JSONArray()
                    .put(JSONObject().put("kind", "A").put("name", "ns").put("value", "203.0.113.7"))
                    .put(JSONObject().put("kind", "NS").put("name", "t").put("value", "ns.example.com")),
            ),
        )
        answers["dns"] = listOf(done("status" to "right"))
        val m = model()
        fill(m, masterdns = true)
        m.submit()
        m.trustIdentity()
        val dns = m.screen as MsScreen.Dns
        assertEquals(listOf("A", "NS"), dns.records.map { it.kind })
        assertTrue(requests.none { it.getString("op") == "install" })
        m.checkDns()
        assertEquals("ns.example.com", requests.last().getString("ns_host"))
        assertEquals(DnsStatus.Right, (m.screen as MsScreen.Dns).status)
    }

    @Test
    fun `usage keeps the figures per server and a failed read keeps the last good ones`() {
        val m = model()
        MyServerStore.get(context).put(MyServerStore.Entry(record(), JSONArray()))
        m.entries.add(MyServerStore.Entry(record(), JSONArray()))
        answers["usage"] = listOf(
            done(
                "usage" to JSONObject().put("window_secs", 300).put(
                    "inbounds",
                    JSONArray().put(
                        JSONObject().put("tag", "reality-in").put("sessions", 3).put("devices_now", 2)
                            .put("devices_recent", 4).put("uplink", 10).put("downlink", 20),
                    ),
                ),
            ),
        )
        runBlocking { m.refreshUsage("srv1") }
        val first = m.usage.getValue("srv1")
        assertEquals(2L, first.inbounds.single().now)
        assertEquals(4L, first.inbounds.single().recent)
        answers["usage"] = listOf(fail("The server program is not running."))
        runBlocking { m.refreshUsage("srv1") }
        assertEquals(first, m.usage.getValue("srv1"))
        assertEquals("The server program is not running.", m.usageError["srv1"])
    }

    @Test
    fun `removing deletes the record only after the core says the server is clean`() {
        val m = model()
        val entry = MyServerStore.Entry(record(), JSONArray())
        MyServerStore.get(context).put(entry)
        m.entries.add(entry)
        answers["remove"] = listOf(fail("Could not log in."))
        m.remove("srv1")
        assertEquals(MsScreen.Server("srv1"), m.screen)
        assertEquals(listOf("srv1"), MyServerStore.get(context).load().map { it.id })
        answers["remove"] = listOf(done())
        m.remove("srv1")
        waitFor("the list") { m.screen == MsScreen.List }
        assertTrue(m.entries.isEmpty())
        assertTrue(MyServerStore.get(context).load().isEmpty())
    }

    @Test
    fun `closing the page keeps an install running and reopening shows its progress`() {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val slow = MyServerModel(
            context = context,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
            run = { request ->
                flow {
                    if (request.getString("op") == "install") gate.await()
                    emit(done("fingerprint" to "SHA256:abc", "algorithm" to "ssh-ed25519"))
                }
            },
            importLink = { true },
            notify = {},
        )
        fill(slow)
        slow.submit()
        slow.trustIdentity()
        assertTrue(slow.screen is MsScreen.Progress)
        slow.back()
        assertFalse(slow.open)
        slow.show()
        assertTrue(slow.screen is MsScreen.Progress)
        gate.cancel()
    }
}
