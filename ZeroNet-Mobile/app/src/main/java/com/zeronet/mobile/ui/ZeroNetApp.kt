package com.zeronet.mobile.ui

import android.provider.Settings as SystemSettings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.togetherWith
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.model.MotionLevel
import com.zeronet.mobile.ui.components.rememberGlassAllowed
import com.zeronet.mobile.ui.home.HomeRoute
import com.zeronet.mobile.ui.onboarding.OnboardingRoute
import com.zeronet.mobile.ui.scanner.ScannerRoute
import com.zeronet.mobile.ui.servers.ServersRoute
import com.zeronet.mobile.ui.settings.SettingsRoute
import com.zeronet.mobile.ui.shell.Tab
import com.zeronet.mobile.ui.shell.TabHost
import com.zeronet.mobile.ui.shell.ZeroRoot
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.update.UpdateActions
import com.zeronet.mobile.ui.update.UpdateSheet

/**
 * The whole app: theme from settings, first-run onboarding, then the four
 * tabs under the floating bar. [onThemeResolved] lets the activity match the
 * system bar icons to the resolved light/dark theme.
 */
@Composable
fun ZeroNetApp(
    controller: AppController,
    showOnboarding: Boolean,
    onOnboardingFinished: () -> Unit,
    onThemeResolved: (dark: Boolean) -> Unit,
) {
    val settings by controller.settings.settings.collectAsStateWithLifecycle()
    val context = LocalContext.current
    // System "Remove animations" (animator scale 0) counts as reduced motion too.
    val systemReduced = remember {
        runCatching { SystemSettings.Global.getFloat(context.contentResolver, SystemSettings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f }
            .getOrDefault(false)
    }
    ZeroTheme(
        palette = settings.palette,
        themeMode = settings.themeMode,
        dynamicColor = settings.dynamicColor,
        amoled = settings.amoled,
        reducedMotion = settings.motion == MotionLevel.Reduced || systemReduced,
        glass = rememberGlassAllowed(),
        gaming = settings.profile == ConnectionProfile.Gaming,
    ) {
        val dark = ZeroTheme.colors.isDark
        SideEffect { onThemeResolved(dark) }
        CompositionLocalProvider(LocalController provides controller) {
            AnimatedContent(
                targetState = showOnboarding,
                transitionSpec = { (fadeIn(tween(ZeroMotion.ms(320))) + scaleIn(initialScale = 0.97f)) togetherWith fadeOut(tween(ZeroMotion.ms(160))) },
                label = "onboarding",
            ) { onboarding ->
                if (onboarding) {
                    ZeroRoot(showBottomBar = false, tab = controller.tab, onTab = {}, messages = controller.messages) {
                        OnboardingRoute(onFinished = onOnboardingFinished)
                    }
                } else {
                    MainTabs(controller)
                }
            }
        }
    }
}

@Composable
private fun MainTabs(controller: AppController) {
    // Back from any other tab returns Home before leaving the app.
    BackHandler(enabled = controller.tab != Tab.Home) { controller.tab = Tab.Home }
    ZeroRoot(showBottomBar = true, tab = controller.tab, onTab = { controller.tab = it }, messages = controller.messages) {
        TabHost(controller.tab) { tab ->
            when (tab) {
                Tab.Home -> HomeRoute()
                Tab.Servers -> ServersRoute()
                Tab.Scanner -> ScannerRoute()
                Tab.Settings -> SettingsRoute()
            }
        }
        val update by controller.updater.state.collectAsStateWithLifecycle()
        val actions = remember(controller) {
            UpdateActions(
                onUpdate = controller.updater::download,
                onLater = controller::dismissUpdate,
                onCancel = controller.updater::cancel,
                onInstall = controller::installUpdate,
                onOpenPage = controller.platform::openUrl,
                canInstall = controller.updater::canInstall,
            )
        }
        UpdateSheet(controller.updateSheetOpen, update, actions)
    }
}
