package com.zeronet.mobile.ui.myserver

import com.zeronet.mobile.data.MyServerStore
import com.zeronet.mobile.ui.Fixtures
import com.zeronet.mobile.ui.servers.ServersActions
import com.zeronet.mobile.ui.servers.ServersScreen
import com.zeronet.mobile.ui.servers.ServersSegment
import com.zeronet.mobile.ui.servers.ServersState
import com.zeronet.mobile.ui.shell.Tab
import com.zeronet.mobile.ui.shot
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

private const val PHONE = "w411dp-h891dp-xxhdpi"
private const val FA = "fa-rIR-ldrtl"

/**
 * Screenshots of every screen of the "My server" page, reached the way a
 * person reaches them (through the model, with a scripted core), recorded to
 * app/build/outputs/roborazzi.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = PHONE)
class MyServerShotsTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = RuntimeEnvironment.getApplication()
    private val answers = mutableMapOf<String, List<JSONObject>>()

    @Before
    fun fresh() {
        MyServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        File(context.noBackupFilesDir, "my-servers.json").delete()
        answers.clear()
        answers["fingerprint"] = listOf(ok("fingerprint" to "SHA256:Tq3d9Yk0lWmZ1u8h2sP7xBvN4c5eRfA6gJ0oIiLkU1w", "algorithm" to "ssh-ed25519"))
        answers["dns_plan"] = listOf(
            ok(
                "domain" to "t.example.com", "ns_host" to "ns.example.com", "needs_ip" to false,
                "records" to JSONArray()
                    .put(JSONObject().put("kind", "A").put("name", "ns").put("value", "203.0.113.7"))
                    .put(JSONObject().put("kind", "NS").put("name", "t").put("value", "ns.example.com")),
            ),
        )
        answers["usage"] = listOf(
            ok(
                "usage" to JSONObject().put("window_secs", 300).put(
                    "inbounds",
                    JSONArray().put(
                        JSONObject().put("tag", "reality-in").put("sessions", 5).put("devices_now", 3)
                            .put("devices_recent", 7).put("uplink", 48_000_000).put("downlink", 912_000_000),
                    ).put(
                        JSONObject().put("tag", "xhttp-in").put("sessions", 2).put("devices_now", 1)
                            .put("devices_recent", 2).put("uplink", 6_000_000).put("downlink", 130_000_000),
                    ),
                ),
            ),
        )
    }

    private fun ok(vararg f: Pair<String, Any>) = JSONObject().put("t", "done").put("ok", true).also { o -> f.forEach { o.put(it.first, it.second) } }

    private fun record(services: List<String> = listOf("reality")) = JSONObject()
        .put("id", "srv1").put("name", "Frankfurt VPS").put("host", "203.0.113.7")
        .put(
            "services",
            JSONArray().also { a ->
                services.forEach { a.put(JSONObject().put("kind", it).put("tag", when (it) { "reality" -> "reality-in"; "xhttp" -> "xhttp-in"; else -> "masterdns" })) }
            },
        )

    private fun configs(services: List<String>) = JSONArray().also { a ->
        services.forEach {
            a.put(
                if (it == "xhttp") {
                    JSONObject().put("service", "xhttp").put("user", "Main")
                        .put("link", "vless://6f1d2c3e-aaaa-bbbb-cccc-0123456789ab@203.0.113.7:8443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=Zk3Qx9wTn2LmV8aYc7Rb4HdJ1sUeP6oFgA5iKtN0yXw&sid=ab12cd34&type=xhttp&path=%2F4f7d5c16&mode=auto#Frankfurt%20XHTTP")
                        .put("files", JSONArray())
                } else if (it == "reality") {
                    JSONObject().put("service", "reality").put("user", "Main")
                        .put("link", "vless://6f1d2c3e-aaaa-bbbb-cccc-0123456789ab@203.0.113.7:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=Zk3Qx9wTn2LmV8aYc7Rb4HdJ1sUeP6oFgA5iKtN0yXw&sid=ab12cd34#Frankfurt")
                        .put("files", JSONArray())
                } else {
                    JSONObject().put("service", "masterdns").put("user", "Main").put("link", JSONObject.NULL)
                        .put("files", JSONArray().put(JSONObject().put("name", "client_config.toml").put("text", "DOMAINS = [\"t.example.com\"]\nENCRYPTION_KEY = \"…\"\n")))
                }
            )
        }
    }

    private fun model(saved: Boolean = true, services: List<String> = listOf("reality")): MyServerModel {
        if (saved) MyServerStore.get(context).put(MyServerStore.Entry(record(services), configs(services)))
        val m = MyServerModel(
            context = context,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
            run = ::core,
            importLink = { true },
            notify = {},
        )
        if (saved) {
            val end = System.currentTimeMillis() + 5_000
            while (m.entries.isEmpty() && System.currentTimeMillis() < end) Thread.sleep(10)
        }
        m.show()
        return m
    }

    private fun core(request: JSONObject): Flow<JSONObject> = flow {
        answers[request.getString("op")].orEmpty().forEach { emit(it) }
    }

    private fun shot(name: String, dark: Boolean = true, qr: Boolean = false, m: MyServerModel) =
        compose.shot(name, dark = dark, tab = Tab.Servers, bar = false, waitForQr = qr) {
            ServersScreen(ServersState(servers = Fixtures.servers, subscriptions = emptyList(), segment = ServersSegment.Recommended), ServersActions())
            MyServerSheet(m)
        }

    private fun fill(m: MyServerModel, masterdns: Boolean) {
        m.startAdd()
        m.form.address = "203.0.113.7"
        m.form.password = "hunter2"
        m.form.reality = !masterdns
        m.form.masterdns = masterdns
        if (masterdns) m.form.domain = "t.example.com"
    }

    @Test fun ms_0_list_empty() = shot("ms_0_list_empty", m = model(saved = false))
    @Test fun ms_1_list() = shot("ms_1_list", m = model())
    @Test fun ms_2_form() = model(saved = false).let { m -> m.startAdd(); shot("ms_2_form", m = m) }
    @Test fun ms_2_form_masterdns_light() = model(saved = false).let { m -> fill(m, true); shot("ms_2_form_masterdns_light", dark = false, m = m) }
    @Test fun ms_2_form_key() = model(saved = false).let { m ->
        m.startAdd(); m.form.useKey = true; m.form.keyText = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----"
        shot("ms_2_form_key", m = m)
    }
    @Test fun ms_3_identity() = model(saved = false).let { m -> fill(m, false); m.submit(); shot("ms_3_identity", m = m) }
    @Test fun ms_4_dns() = model(saved = false).let { m -> fill(m, true); m.submit(); m.trustIdentity(); shot("ms_4_dns", m = m) }
    @Test fun ms_5_server() = model().let { m ->
        m.openServer("srv1")
        runBlocking { m.refreshUsage("srv1") }
        shot("ms_5_server", m = m)
    }
    @Test fun ms_6_confirm_remove() = model().let { m -> m.openServer("srv1"); m.askRemove("srv1"); shot("ms_6_confirm_remove", m = m) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun ms_7_form_fa() = model(saved = false).let { m -> m.startAdd(); shot("ms_7_form_fa", m = m) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun ms_8_server_fa() = model().let { m ->
        m.openServer("srv1")
        runBlocking { m.refreshUsage("srv1") }
        shot("ms_8_server_fa", m = m)
    }

    @Test fun ms_9_server_masterdns() = model(services = listOf("reality", "xhttp", "master_dns")).let { m ->
        m.openServer("srv1")
        runBlocking { m.refreshUsage("srv1") }
        shot("ms_9_server_masterdns", dark = false, m = m)
    }
}
