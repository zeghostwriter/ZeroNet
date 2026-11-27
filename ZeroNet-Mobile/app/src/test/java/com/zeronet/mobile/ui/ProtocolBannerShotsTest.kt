package com.zeronet.mobile.ui

import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.ThemeMode
import com.zeronet.mobile.ui.shell.Tab
import com.zeronet.mobile.ui.shell.ZeroRoot
import com.zeronet.mobile.ui.theme.ZeroTheme
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import com.zeronet.mobile.ui.home.HomeScreen
import com.zeronet.mobile.ui.home.HomeState
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

private const val PHONE = "w411dp-h891dp-xxhdpi"
private const val SMALL_PHONE = "w360dp-h780dp-xxhdpi"

/** The protocol banner above the globe, at the moments worth looking at. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = PHONE)
class ProtocolBannerShotsTest {
    @get:Rule
    val compose = createComposeRule()

    private fun server(protocol: String, transport: String, security: String) =
        Fixtures.germany.copy(protocol = protocol, transport = transport, security = security)

    private fun home(server: Server) = HomeState(
        conn = ConnState.Connected(server = server, since = Fixtures.NOW - 754_000, delayMs = 142, pool = 1),
        stats = Fixtures.stats,
        now = Fixtures.NOW,
    )

    private fun shot(name: String, server: Server, advanceMs: Long = 1_900, dark: Boolean = true) =
        compose.shot(name, dark = dark, advanceMs = advanceMs) { HomeScreen(home(server), {}, {}, {}) }

    @Test fun banner_reality() = shot("banner_reality", server("vless", "tcp", "reality"))
    @Test fun banner_reality_light() = shot("banner_reality_light", server("vless", "tcp", "reality"), dark = false)
    @Test fun banner_xhttp_reality_reveal() = shot("banner_xhttp_reality_reveal", server("vless", "xhttp", "reality"), advanceMs = 650)
    @Test fun banner_xhttp_reality() = shot("banner_xhttp_reality", server("vless", "xhttp", "reality"))
    @Test fun banner_custom() = shot("banner_custom", server("", "", ""))
    @Test fun banner_hysteria() = shot("banner_hysteria", server("hysteria2", "quic", "tls"))
    @Test fun banner_trojan() = shot("banner_trojan", server("trojan", "tcp", "tls"))
    @Test fun banner_vmess() = shot("banner_vmess", server("vmess", "ws", "tls"))
    @Test fun banner_masterdns() = shot("banner_masterdns", server("masterdns", "tcp", "none"))
    /** The same banner on the pure-black (AMOLED) theme, where the VPN letters are true black. */
    @Test fun banner_masterdns_amoled() {
        compose.mainClock.autoAdvance = false
        compose.setContent {
            ZeroTheme(themeMode = ThemeMode.Dark, amoled = true) {
                ZeroRoot(showBottomBar = true, tab = Tab.Home, onTab = {}) {
                    HomeScreen(home(server("masterdns", "tcp", "none")), {}, {}, {})
                }
            }
        }
        compose.mainClock.advanceTimeBy(1_900)
        compose.onRoot().captureRoboImage("build/outputs/roborazzi/banner_masterdns_amoled.png")
    }
    @Test fun banner_tuic() = shot("banner_tuic", server("tuic", "quic", "tls"))

    @Config(qualifiers = SMALL_PHONE)
    @Test fun banner_long_on_a_small_phone() = shot("banner_long_360", server("vless", "httpupgrade", "reality"))
}
