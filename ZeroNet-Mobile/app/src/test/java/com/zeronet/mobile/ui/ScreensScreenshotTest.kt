package com.zeronet.mobile.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.ConnectTarget
import com.zeronet.mobile.model.DiscoveryProgress
import com.zeronet.mobile.model.DiscoveryStage
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.model.ThemeMode
import com.zeronet.mobile.ui.components.QR_READY_TAG
import com.zeronet.mobile.ui.home.HomeScreen
import com.zeronet.mobile.ui.home.HomeState
import com.zeronet.mobile.ui.onboarding.OnboardingScreen
import com.zeronet.mobile.ui.scanner.ScannerActions
import com.zeronet.mobile.ui.scanner.ScannerScreen
import com.zeronet.mobile.ui.servers.ServerDetailSheet
import com.zeronet.mobile.ui.servers.ServersActions
import com.zeronet.mobile.ui.servers.ServersScreen
import com.zeronet.mobile.ui.servers.ServersSegment
import com.zeronet.mobile.ui.servers.ServersState
import com.zeronet.mobile.ui.settings.SettingsActions
import com.zeronet.mobile.ui.settings.SettingsCardId
import com.zeronet.mobile.ui.settings.SettingsScreen
import com.zeronet.mobile.ui.settings.SettingsUiState
import com.zeronet.mobile.ui.shell.Tab
import com.zeronet.mobile.ui.shell.ZeroRoot
import com.zeronet.mobile.ui.theme.ZeroTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

private const val PHONE = "w411dp-h891dp-xxhdpi"
private const val SMALL_PHONE = "w360dp-h780dp-xxhdpi"
private const val FA = "fa-rIR-ldrtl"

/**
 * JVM screenshots of the stateless screens (Robolectric native graphics +
 * Roborazzi). Record with `./gradlew recordRoborazziDebug`; images land in
 * app/build/outputs/roborazzi.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = PHONE)
class ScreensScreenshotTest {

    @get:Rule
    val compose = createComposeRule()

    // ---------------------------------------------------------------- Home

    private val connected = ConnState.Connected(server = Fixtures.germany, since = Fixtures.NOW - 754_000, delayMs = 142, pool = 6)

    private fun home(conn: ConnState) = HomeState(
        conn = conn,
        stats = if (conn is ConnState.Connected) Fixtures.stats else com.zeronet.mobile.model.TrafficStats(),
        target = ConnectTarget.Fastest,
        now = Fixtures.NOW,
    )

    private val searching = ConnState.Searching(
        DiscoveryProgress(stage = DiscoveryStage.Real, candidates = 1_840, tcpDone = 412, tcpOpen = 96, realDone = 64, alive = 7),
    )

    @Test fun home_idle_dark() = compose.shot("home_idle_dark") { HomeScreen(home(ConnState.Idle), {}, {}, {}) }

    @Test fun home_idle_light() = compose.shot("home_idle_light", dark = false) { HomeScreen(home(ConnState.Idle), {}, {}, {}) }

    @Test fun home_searching_dark() = compose.shot("home_searching_dark", advanceMs = 900) { HomeScreen(home(searching), {}, {}, {}) }

    @Test fun home_connected_dark() = compose.shot("home_connected_dark") { HomeScreen(home(connected), {}, {}, {}) }

    @Test fun home_connected_light() = compose.shot("home_connected_light", dark = false) { HomeScreen(home(connected), {}, {}, {}) }

    @Test fun home_failed_dark() = compose.shot("home_failed_dark") {
        HomeScreen(home(ConnState.Failed(FailReason.NoWorkingServer, "")), {}, {}, {})
    }

    @Config(qualifiers = SMALL_PHONE)
    @Test fun home_connected_360_dark() = compose.shot("home_connected_360_dark") { HomeScreen(home(connected), {}, {}, {}) }

    @Config(qualifiers = SMALL_PHONE)
    @Test fun home_failed_360_light() = compose.shot("home_failed_360_light", dark = false) {
        HomeScreen(home(ConnState.Failed(FailReason.NoWorkingServer, "")), {}, {}, {})
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun home_connected_fa_dark() = compose.shot("home_connected_fa_dark") { HomeScreen(home(connected), {}, {}, {}) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun home_searching_fa_light() = compose.shot("home_searching_fa_light", dark = false, advanceMs = 900) {
        HomeScreen(home(searching), {}, {}, {})
    }

    // ---------------------------------------------------------------- Servers

    private fun servers(segment: ServersSegment, list: Boolean = true) = ServersState(
        servers = if (list) Fixtures.servers else emptyList(),
        subscriptions = if (list) Fixtures.subscriptions else emptyList(),
        segment = segment,
        expanded = setOf("DE"),
        activeKey = "de1",
        now = Fixtures.NOW,
    )

    @Test fun servers_recommended_dark() = compose.shot("servers_recommended_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended), ServersActions())
    }

    @Test fun servers_recommended_light() = compose.shot("servers_recommended_light", dark = false, tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended).copy(testProgress = 37 to 120), ServersActions())
    }

    @Test fun servers_countries_dark() = compose.shot("servers_countries_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Countries), ServersActions())
    }

    @Test fun servers_mine_dark() = compose.shot("servers_mine_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Mine), ServersActions())
    }

    @Test fun servers_empty_dark() = compose.shot("servers_empty_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended, list = false), ServersActions())
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun servers_recommended_fa_dark() = compose.shot("servers_recommended_fa_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended), ServersActions())
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun servers_countries_fa_light() = compose.shot("servers_countries_fa_light", dark = false, tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Countries), ServersActions())
    }

    @Test fun server_detail_dark() = compose.shot("server_detail_dark", tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended), ServersActions())
        ServerDetailSheet(
            server = Fixtures.servers.first { it.key == "my1" },
            subscriptions = Fixtures.subscriptions,
            testing = false,
            now = Fixtures.NOW,
            onConnect = {}, onTest = {}, onCopyLink = {}, onFavorite = { _, _ -> }, onDelete = {}, onDismiss = {},
        )
    }

    @Test fun server_detail_light() = compose.shot("server_detail_light", dark = false, tab = Tab.Servers) {
        ServersScreen(servers(ServersSegment.Recommended), ServersActions())
        ServerDetailSheet(
            server = Fixtures.germany,
            subscriptions = Fixtures.subscriptions,
            testing = false,
            now = Fixtures.NOW,
            onConnect = {}, onTest = {}, onCopyLink = {}, onFavorite = { _, _ -> }, onDelete = {}, onDismiss = {},
        )
    }

    // ---------------------------------------------------------------- Updates

    private val release = com.zeronet.mobile.update.ReleaseInfo(
        version = "0.2.0",
        page = "https://github.com/zeghostwriter/ZeroNet/releases/tag/v0.2.0",
        notes = listOf(
            "Server tests: survive Iran's forged DNS and Cloudflare Workers",
            "README: fix right-to-left layout of the Persian section",
            "In-app updates for the desktop and Android apps",
        ),
        apkName = "ZeroNet-Android-arm64-v8a.apk",
        apkUrl = "https://example.invalid/ZeroNet-Android-arm64-v8a.apk",
        apkSize = 8_484_895,
        sha256 = null,
    )

    private val updateActions = com.zeronet.mobile.ui.update.UpdateActions({}, {}, {}, {}, {}, { true })

    @Test fun update_offer_dark() = compose.shot("update_offer_dark") {
        HomeScreen(home(ConnState.Idle), {}, {}, {})
        com.zeronet.mobile.ui.update.UpdateSheet(true, com.zeronet.mobile.update.UpdateState.Available(release), updateActions)
    }

    @Test fun update_downloading_light() = compose.shot("update_downloading_light", dark = false) {
        HomeScreen(home(connected), {}, {}, {})
        com.zeronet.mobile.ui.update.UpdateSheet(
            true,
            com.zeronet.mobile.update.UpdateState.Downloading(release, 5_400_000, release.apkSize),
            updateActions,
        )
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun update_ready_fa_dark() = compose.shot("update_ready_fa_dark") {
        HomeScreen(home(connected), {}, {}, {})
        com.zeronet.mobile.ui.update.UpdateSheet(
            true,
            com.zeronet.mobile.update.UpdateState.Ready(release, java.io.File("ZeroNet.apk")),
            updateActions,
        )
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun update_offer_fa_light() = compose.shot("update_offer_fa_light", dark = false) {
        HomeScreen(home(ConnState.Idle), {}, {}, {})
        com.zeronet.mobile.ui.update.UpdateSheet(true, com.zeronet.mobile.update.UpdateState.Available(release), updateActions)
    }

    // ---------------------------------------------------------------- Scanner

    @Test fun scanner_idle_dark() = compose.shot("scanner_idle_dark", tab = Tab.Scanner) { ScannerScreen(ScanState(), ScannerActions()) }

    @Test fun scanner_running_dark() = compose.shot("scanner_running_dark", tab = Tab.Scanner) { ScannerScreen(Fixtures.scanRunning, ScannerActions()) }

    @Test fun scanner_running_light() = compose.shot("scanner_running_light", dark = false, tab = Tab.Scanner) {
        ScannerScreen(Fixtures.scanRunning, ScannerActions())
    }

    // ---------------------------------------------------------------- Settings

    private fun settingsState(settings: Settings = Settings(), lan: List<String> = emptyList()) = SettingsUiState(
        settings = settings,
        connected = true,
        reconnectCards = setOf(SettingsCardId.Connection),
        subscriptions = Fixtures.subscriptions,
        knownCountries = listOf("DE", "NL", "FI"),
        discoveredCount = 11,
        lanAddresses = lan,
        versionName = "0.1.0",
        versionCode = 1,
    )

    private val tuned = Settings(preferredCountries = listOf("DE", "NL"), mode = com.zeronet.mobile.model.ConnectionMode.Proxy)

    @Test fun settings_dark() = compose.shot("settings_dark", tab = Tab.Settings) { SettingsScreen(settingsState(tuned), SettingsActions()) }

    @Test fun settings_light() = compose.shot("settings_light", dark = false, tab = Tab.Settings) { SettingsScreen(settingsState(tuned), SettingsActions()) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun settings_fa_dark() = compose.shot("settings_fa_dark", tab = Tab.Settings) { SettingsScreen(settingsState(tuned), SettingsActions()) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun settings_fa_light() = compose.shot("settings_fa_light", dark = false, tab = Tab.Settings) {
        SettingsScreen(settingsState(tuned), SettingsActions())
    }

    @Test fun settings_connection_more_dark() = compose.shot("settings_connection_more_dark", tab = Tab.Settings) {
        SettingsScreen(
            settingsState(Settings(killSwitch = true, trustedNetworks = listOf("0011223344556677|Home Wi-Fi"))),
            SettingsActions(),
            initialSheet = com.zeronet.mobile.ui.settings.SettingsSheet.ConnectionMore,
        )
    }

    private val diagnosis = com.zeronet.mobile.model.Diagnosis(
        running = false,
        finishedAt = Fixtures.NOW,
        checks = listOf(
            com.zeronet.mobile.model.DiagCheck("network", com.zeronet.mobile.model.CheckStatus.Ok, "Irancell (IR)"),
            com.zeronet.mobile.model.DiagCheck("internet", com.zeronet.mobile.model.CheckStatus.Ok, "HTTP 204"),
            com.zeronet.mobile.model.DiagCheck("dns", com.zeronet.mobile.model.CheckStatus.Bad, "www.youtube.com → 10.10.34.35"),
            com.zeronet.mobile.model.DiagCheck("tls", com.zeronet.mobile.model.CheckStatus.Bad, "SNI filtering: www.youtube.com connection reset during the handshake"),
            com.zeronet.mobile.model.DiagCheck("family_split", com.zeronet.mobile.model.CheckStatus.Ok, "3 of 4 answered, best 212 ms"),
            com.zeronet.mobile.model.DiagCheck("family_direct", com.zeronet.mobile.model.CheckStatus.Warn, "1 of 4 answered, best 340 ms"),
            com.zeronet.mobile.model.DiagCheck("family_cdn", com.zeronet.mobile.model.CheckStatus.Bad, "0 of 4 answered"),
            com.zeronet.mobile.model.DiagCheck("family_quic", com.zeronet.mobile.model.CheckStatus.Skipped, "no saved servers of this kind"),
            com.zeronet.mobile.model.DiagCheck("family_other", com.zeronet.mobile.model.CheckStatus.Running, "1 of 4"),
        ),
    )

    @Test fun settings_diagnostics_dark() = compose.shot("settings_diagnostics_dark", tab = Tab.Settings) {
        SettingsScreen(settingsState().copy(diagnosis = diagnosis), SettingsActions(), initialSheet = com.zeronet.mobile.ui.settings.SettingsSheet.Diagnostics)
    }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun settings_diagnostics_fa_light() = compose.shot("settings_diagnostics_fa_light", dark = false, tab = Tab.Settings) {
        SettingsScreen(settingsState().copy(diagnosis = diagnosis), SettingsActions(), initialSheet = com.zeronet.mobile.ui.settings.SettingsSheet.Diagnostics)
    }

    @Test fun settings_logs_dark() = compose.shot("settings_logs_dark", tab = Tab.Settings) {
        SettingsScreen(settingsState(), SettingsActions(), initialSheet = com.zeronet.mobile.ui.settings.SettingsSheet.Logs)
    }

    @Test fun settings_diagnostics_card_light() = compose.shot("settings_diagnostics_card_light", dark = false, tab = Tab.Settings) {
        SettingsScreen(settingsState(), SettingsActions(), initialQuery = "logs")
    }

    @Test fun settings_share_dark() = compose.shot("settings_share_dark", tab = Tab.Settings, waitForQr = true) {
        SettingsScreen(settingsState(Settings(lanShare = true), lan = listOf("192.168.1.34")), SettingsActions(), initialQuery = "hotspot")
    }

    @Test fun settings_share_password_light() = compose.shot("settings_share_password_light", dark = false, tab = Tab.Settings, waitForQr = true) {
        SettingsScreen(
            settingsState(Settings(lanShare = true, lanUser = "guest", lanPass = "s3cret"), lan = listOf("192.168.43.1")),
            SettingsActions(),
            initialQuery = "hotspot",
        )
    }

    // ---------------------------------------------------------------- Onboarding

    @Test fun onboarding_dark() = compose.shot("onboarding_dark", bar = false) { OnboardingScreen(onAllow = {}, onLater = {}) }

    @Test fun onboarding_light() = compose.shot("onboarding_light", dark = false, bar = false) { OnboardingScreen(onAllow = {}, onLater = {}) }

    @Config(qualifiers = "$FA-$PHONE")
    @Test fun onboarding_fa_dark() = compose.shot("onboarding_fa_dark", bar = false) { OnboardingScreen(onAllow = {}, onLater = {}) }
}

/**
 * Renders [content] inside the real app chrome (theme, floating bar, sheet
 * overlay) with the animation clock paused, lets springs settle for
 * [advanceMs], then records the window.
 */
fun ComposeContentTestRule.shot(
    name: String,
    dark: Boolean = true,
    tab: Tab = Tab.Home,
    bar: Boolean = true,
    advanceMs: Long = 1_600,
    waitForQr: Boolean = false,
    content: @Composable () -> Unit,
) {
    mainClock.autoAdvance = false
    setContent {
        ZeroTheme(themeMode = if (dark) ThemeMode.Dark else ThemeMode.Light) {
            ZeroRoot(showBottomBar = bar, tab = tab, onTab = {}) { content() }
        }
    }
    mainClock.advanceTimeBy(advanceMs)
    if (waitForQr) {
        waitUntil(10_000) {
            mainClock.advanceTimeBy(16)
            onAllNodesWithTag(QR_READY_TAG, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        mainClock.advanceTimeBy(500)
    }
    onRoot().captureRoboImage("build/outputs/roborazzi/$name.png")
}
