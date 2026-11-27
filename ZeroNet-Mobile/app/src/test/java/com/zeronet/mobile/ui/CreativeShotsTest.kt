package com.zeronet.mobile.ui

import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.model.Diagnosis
import com.zeronet.mobile.model.LaneFail
import com.zeronet.mobile.model.LaneOutcome
import com.zeronet.mobile.model.RaceLane
import com.zeronet.mobile.model.RaceState
import com.zeronet.mobile.model.WarpPhase
import com.zeronet.mobile.model.WarpState
import com.zeronet.mobile.service.Diagnostics
import com.zeronet.mobile.ui.home.HomeScreen
import com.zeronet.mobile.ui.home.HomeState
import com.zeronet.mobile.ui.servers.ServersActions
import com.zeronet.mobile.ui.servers.ServersScreen
import com.zeronet.mobile.ui.servers.ServersSegment
import com.zeronet.mobile.ui.servers.ServersState
import com.zeronet.mobile.ui.servers.WarpSheet
import com.zeronet.mobile.ui.settings.DiagnosticsSheet
import com.zeronet.mobile.ui.shell.Tab
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

private const val PHONE = "w411dp-h891dp-xxhdpi"
private const val FINGERPRINT = "3FA9 C0D1 7B42 E8A5 0F1E 2D3C 4B5A 6978"

/** Screenshots of the race lanes, the path map, the WARP sheet and the account picture. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = PHONE)
class CreativeShotsTest {
    @get:Rule
    val compose = createComposeRule()

    private val warpServer = Fixtures.germany.copy(
        key = "warp1", name = "Cloudflare WARP", protocol = "amnezia-wg", country = "", fingerprint = FINGERPRINT,
    )

    private val race = RaceState(
        serial = 5, done = true, nowMs = 1500,
        lanes = listOf(
            RaceLane("wireguard", LaneOutcome.Lost, LaneFail.NoAnswer, 0, 1100),
            RaceLane("masque-h3", LaneOutcome.Lost, LaneFail.Refused, 200, 280),
            RaceLane("masque-h2", LaneOutcome.Won, null, 400, 1300),
        ),
    )

    private fun home(race: RaceState) = HomeState(
        conn = ConnState.Connected(server = warpServer, since = Fixtures.NOW - 90_000, delayMs = 260, pool = 1),
        stats = Fixtures.stats,
        target = ConnectTarget.Fastest,
        now = Fixtures.NOW,
        race = race,
    )

    @Test fun race_home_start() = compose.shot("race_home_0_start", advanceMs = 300) { HomeScreen(home(race), {}, {}, {}) }
    @Test fun race_home_mid() = compose.shot("race_home_1_mid", advanceMs = 1700) { HomeScreen(home(race), {}, {}, {}) }
    @Test fun race_home_end() = compose.shot("race_home_2_end", advanceMs = 5200) { HomeScreen(home(race), {}, {}, {}) }
    @Test fun race_home_light() = compose.shot("race_home_light", dark = false, advanceMs = 5200) { HomeScreen(home(race), {}, {}, {}) }
    @Test fun race_home_failed() = compose.shot(
        "race_home_failed",
        advanceMs = 5200,
    ) {
        HomeScreen(
            home(
                RaceState(
                    serial = 6, done = true, nowMs = 6000,
                    lanes = listOf(
                        RaceLane("wireguard", LaneOutcome.Lost, LaneFail.NoAnswer, 0, 6000),
                        RaceLane("masque-h3", LaneOutcome.Lost, LaneFail.NoAnswer, 200, 6200),
                        RaceLane("masque-h2", LaneOutcome.Lost, LaneFail.NoTraffic, 400, 6400),
                    ),
                ),
            ),
            {}, {}, {},
        )
    }

    // ------------------------------------------------------------ path map

    private fun diag(
        network: CheckStatus = CheckStatus.Ok,
        internet: CheckStatus = CheckStatus.Ok,
        dns: CheckStatus = CheckStatus.Ok,
        tls: CheckStatus = CheckStatus.Ok,
        tunnel: CheckStatus? = null,
        direct: CheckStatus = CheckStatus.Ok,
        running: Boolean = false,
    ) = Diagnosis(
        running = running,
        checks = buildList {
            add(DiagCheck(Diagnostics.NETWORK, network))
            add(DiagCheck(Diagnostics.INTERNET, internet, if (internet == CheckStatus.Warn) "redirected to http://10.10.34.34" else ""))
            add(DiagCheck(Diagnostics.DNS, dns, if (dns == CheckStatus.Bad) "www.youtube.com → 10.10.34.35" else ""))
            add(DiagCheck(Diagnostics.TLS, tls, if (tls == CheckStatus.Bad) "SNI filtering: www.youtube.com connection reset during the handshake" else ""))
            tunnel?.let { add(DiagCheck(Diagnostics.TUNNEL, it)) }
            add(DiagCheck(Diagnostics.FAMILY_PREFIX + "direct", direct))
            add(DiagCheck(Diagnostics.FAMILY_PREFIX + "cdn", direct))
        },
    )

    private fun sheet(name: String, d: Diagnosis, advanceMs: Long = 2500, dark: Boolean = true) =
        compose.shot(name, dark = dark, tab = Tab.Settings, advanceMs = advanceMs) {
            DiagnosticsSheet(visible = true, diagnosis = d, onRun = {}, onLogs = {}, onDismiss = {})
        }

    @Test fun path_idle() = sheet("path_0_idle", Diagnosis())
    @Test fun path_running() = sheet(
        "path_1_running",
        diag(internet = CheckStatus.Running, dns = CheckStatus.Pending, tls = CheckStatus.Pending, direct = CheckStatus.Pending, running = true),
    )
    @Test fun path_dns() = sheet("path_2_dns", diag(dns = CheckStatus.Bad, tunnel = CheckStatus.Ok))
    @Test fun path_sni() = sheet("path_3_sni", diag(tls = CheckStatus.Bad, tunnel = CheckStatus.Ok))
    @Test fun path_sni_light() = sheet("path_3_sni_light", diag(tls = CheckStatus.Bad, tunnel = CheckStatus.Ok), dark = false)
    @Test fun path_no_server() = sheet("path_4_no_server", diag(direct = CheckStatus.Bad))
    @Test fun path_all_ok() = sheet("path_5_ok", diag())
    @Test fun path_offline() = sheet("path_6_offline", diag(network = CheckStatus.Bad, internet = CheckStatus.Bad, dns = CheckStatus.Bad, tls = CheckStatus.Bad, direct = CheckStatus.Bad))

    // ----------------------------------------------------------- WARP sheet

    private fun warp(name: String, state: WarpState, advanceMs: Long) =
        compose.shot(name, tab = Tab.Servers, advanceMs = advanceMs) {
            ServersScreen(ServersState(servers = Fixtures.servers, subscriptions = emptyList(), segment = ServersSegment.Recommended), ServersActions())
            WarpSheet(visible = true, state = state, onStart = {}, onCancel = {}, onDismiss = {})
        }

    @Test fun warp_offer() = warp("warp_0_offer", WarpState(), 1500)
    @Test fun warp_working() = warp("warp_1_working", WarpState(WarpPhase.Working, listOf("registering")), 1900)
    @Test fun warp_revealing() = warp("warp_2_revealing", WarpState(WarpPhase.Working), 1900)
    @Test fun warp_done() = warp(
        "warp_3_done",
        WarpState(WarpPhase.Done, emptyList(), FINGERPRINT, servers = 3, route = "auto"),
        6500,
    )
    @Test fun warp_failed() = warp("warp_4_failed", WarpState(WarpPhase.Failed, emptyList(), error = "try again"), 1500)

    // ------------------------------------------------------ account picture

    @Test fun servers_with_a_warp_account() = compose.shot("glyph_servers", tab = Tab.Servers) {
        ServersScreen(
            ServersState(servers = listOf(warpServer.copy(source = com.zeronet.mobile.model.Server.SOURCE_USER)) + Fixtures.servers, subscriptions = emptyList(), segment = ServersSegment.Mine),
            ServersActions(),
        )
    }

    // ----------------------------------------------------------- the space

    @Test fun space_home_idle() = compose.shot("space_idle", advanceMs = 2000) { HomeScreen(home(race).copy(conn = ConnState.Idle), {}, {}, {}) }
    @Test fun space_home_light() = compose.shot("space_light", dark = false, advanceMs = 2000) { HomeScreen(home(race).copy(conn = ConnState.Idle), {}, {}, {}) }
    @Test fun space_moon_out() = compose.shot("space_later", advanceMs = 12_000) { HomeScreen(home(race).copy(conn = ConnState.Idle), {}, {}, {}) }

    // ------------------------------------------------------ the lightning

    private fun lightning(name: String, ms: Long) = compose.shot(name, advanceMs = ms) {
        androidx.compose.foundation.layout.Row(
            androidx.compose.ui.Modifier.padding(24.dp),
            horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(16.dp),
        ) {
            com.zeronet.mobile.ui.components.LightningBadge(size = 44.dp)
            com.zeronet.mobile.ui.components.LightningBadge(size = 96.dp)
        }
    }

    @Test fun lightning_rest() = lightning("bolt_0_rest", 2_000)
    @Test fun lightning_strike_early() = lightning("bolt_1_strike", 3_500)
    @Test fun lightning_strike_flicker() = lightning("bolt_2_flicker", 3_560)
    @Test fun lightning_afterglow() = lightning("bolt_3_after", 3_900)

    // ------------------------------------------------------ the controller

    private fun pad(name: String, ms: Long, dark: Boolean = true) = compose.shot(name, dark = dark, tab = Tab.Settings, advanceMs = ms) {
        com.zeronet.mobile.ui.effects.GamepadBurst(1)
    }

    @Test fun gamepad_in() = pad("pad_0_in", 300)
    @Test fun gamepad_buttons() = pad("pad_1_pressing", 1_230)
    @Test fun gamepad_triggers() = pad("pad_2_triggers", 2_020)
    @Test fun gamepad_ignite() = pad("pad_3_ignite", 2_260)
    @Test fun gamepad_words() = pad("pad_4_words", 3_100)
    @Test fun gamepad_words_light() = pad("pad_4_words_light", 3_100, dark = false)

    @Config(qualifiers = "fa-$PHONE")
    @Test fun gamepad_words_fa() = pad("pad_4_words_fa", 3_100)

    @Config(qualifiers = "w360dp-h640dp-xhdpi")
    @Test fun gamepad_words_small() = pad("pad_4_words_small", 3_100)

    /**
     * The scene is started by the profile changing, from wherever the app
     * shell is: here Settings is on screen, as it is for a real person.
     */
    @Test fun gaming_intro_plays_over_settings_when_the_profile_becomes_gaming() {
        var profile by androidx.compose.runtime.mutableStateOf(com.zeronet.mobile.model.ConnectionProfile.Normal)
        val title = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
            .getString(com.zeronet.mobile.R.string.gaming_on_title)
        compose.mainClock.autoAdvance = false
        compose.setContent {
            com.zeronet.mobile.ui.theme.ZeroTheme(themeMode = com.zeronet.mobile.model.ThemeMode.Dark, gaming = profile == com.zeronet.mobile.model.ConnectionProfile.Gaming) {
                androidx.compose.foundation.layout.Box {
                    com.zeronet.mobile.ui.shell.ZeroRoot(showBottomBar = true, tab = Tab.Settings, onTab = {}) {
                        com.zeronet.mobile.ui.settings.SettingsScreen(
                            com.zeronet.mobile.ui.settings.SettingsUiState(settings = com.zeronet.mobile.model.Settings(profile = profile)),
                            com.zeronet.mobile.ui.settings.SettingsActions(onChange = { change -> profile = change(com.zeronet.mobile.model.Settings(profile = profile)).profile }),
                        )
                    }
                    com.zeronet.mobile.ui.effects.GamingIntro(profile)
                }
            }
        }
        compose.mainClock.advanceTimeBy(1_000)
        // Nothing plays for the profile the app opened with.
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(0)

        // The real thing: the person taps Gaming in the Settings list.
        val gaming = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
            .getString(com.zeronet.mobile.R.string.profile_gaming)
        compose.onNode(androidx.compose.ui.test.hasText(gaming)).performClick()
        compose.waitForIdle()
        compose.mainClock.advanceTimeBy(3_100)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(1)
        compose.onRoot().captureRoboImage("build/outputs/roborazzi/pad_5_over_settings.png")

        // It ends by itself and leaves Settings as it was.
        compose.mainClock.advanceTimeBy(1_500)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(0)

        // Leaving gaming and coming back plays it again; leaving in the middle ends it.
        compose.runOnUiThread { profile = com.zeronet.mobile.model.ConnectionProfile.Fast }
        compose.waitForIdle()
        compose.mainClock.advanceTimeBy(300)
        compose.runOnUiThread { profile = com.zeronet.mobile.model.ConnectionProfile.Gaming }
        compose.waitForIdle()
        compose.mainClock.advanceTimeBy(3_100)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(1)
        compose.runOnUiThread { profile = com.zeronet.mobile.model.ConnectionProfile.Normal }
        compose.waitForIdle()
        compose.mainClock.advanceTimeBy(100)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(0)
    }

    @Test fun a_tap_skips_the_gaming_scene_to_its_end() {
        val title = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
            .getString(com.zeronet.mobile.R.string.gaming_on_title)
        compose.mainClock.autoAdvance = false
        compose.setContent {
            com.zeronet.mobile.ui.theme.ZeroTheme(themeMode = com.zeronet.mobile.model.ThemeMode.Dark) {
                com.zeronet.mobile.ui.effects.GamepadBurst(1, androidx.compose.ui.Modifier.testTag("scene"))
            }
        }
        compose.mainClock.advanceTimeBy(900)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(1)
        compose.onNode(androidx.compose.ui.test.hasTestTag("scene")).performClick()
        compose.mainClock.advanceTimeBy(700)
        compose.onAllNodes(androidx.compose.ui.test.hasText(title)).assertCountEquals(0)
    }

    @Test fun with_reduced_motion_the_gaming_scene_is_one_still_picture() {
        compose.mainClock.autoAdvance = false
        compose.setContent {
            com.zeronet.mobile.ui.theme.ZeroTheme(themeMode = com.zeronet.mobile.model.ThemeMode.Dark, reducedMotion = true) {
                com.zeronet.mobile.ui.effects.GamepadBurst(1)
            }
        }
        compose.mainClock.advanceTimeBy(600)
        compose.onRoot().captureRoboImage("build/outputs/roborazzi/pad_6_reduced.png")
    }

    // --------------------------------------------------------------- Mars

    private fun mars(name: String, at: Long) = compose.shot(name, advanceMs = 600) {
        val frame = com.zeronet.mobile.ui.home.MarsTrip.at(at)
        androidx.compose.foundation.layout.Box {
            com.zeronet.mobile.ui.home.Cosmos(warp = frame?.warp ?: 0f)
            com.zeronet.mobile.ui.home.ConnectGlobe(
                phase = com.zeronet.mobile.ui.home.OrbPhase.Idle, label = "CONNECT", actionLabel = "Connect", stateText = "", destination = null,
                gaming = false, gamingTitle = "", hudText = null, onClick = {}, modifier = androidx.compose.ui.Modifier.padding(32.dp), trip = frame,
            )
        }
    }

    @Test fun mars_0_leaving() = mars("mars_0_leaving", 420)
    @Test fun mars_1_racing() = mars("mars_1_racing", 700)
    @Test fun mars_2_arriving() = mars("mars_2_arriving", 1_050)
    @Test fun mars_3_there() = mars("mars_3_there", 9_000)
    @Test fun mars_4_home() = mars("mars_4_home", 25_000)

    // ------------------------------------------------- level of detail

    private fun lod(name: String, frame: com.zeronet.mobile.ui.home.MarsTrip.Frame, ms: Long = 9_000) =
        compose.shot(name, advanceMs = ms) {
            com.zeronet.mobile.ui.home.ConnectGlobe(
                phase = com.zeronet.mobile.ui.home.OrbPhase.Idle, label = "CONNECT", actionLabel = "Connect", stateText = "", destination = null,
                gaming = false, gamingTitle = "", hudText = null, onClick = {}, modifier = androidx.compose.ui.Modifier.padding(32.dp), trip = frame,
            )
        }

    @Test fun lod_mars_close() = lod("lod_mars_1.00", com.zeronet.mobile.ui.home.MarsTrip.Frame(0f, 1f, 0f, false))
    @Test fun lod_mars_medium() = lod("lod_mars_0.55", com.zeronet.mobile.ui.home.MarsTrip.Frame(0f, 0.55f, 0f, false))
    @Test fun lod_mars_far() = lod("lod_mars_0.25", com.zeronet.mobile.ui.home.MarsTrip.Frame(0f, 0.25f, 0f, false))
    @Test fun lod_earth_close() = lod("lod_earth_1.00", com.zeronet.mobile.ui.home.MarsTrip.Frame(1f, 0f, 0f, false))
    @Test fun lod_earth_medium() = lod("lod_earth_0.55", com.zeronet.mobile.ui.home.MarsTrip.Frame(0.55f, 0f, 0f, false))
    @Test fun lod_earth_far() = lod("lod_earth_0.25", com.zeronet.mobile.ui.home.MarsTrip.Frame(0.25f, 0f, 0f, false))
}
