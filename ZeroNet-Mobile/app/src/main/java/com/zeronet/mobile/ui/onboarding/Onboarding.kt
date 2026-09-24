package com.zeronet.mobile.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.LocalController
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.theme.ZeroTheme

/** First run: one screen saying which permissions the app needs, then Android's own prompts. */
@Composable
fun OnboardingRoute(onFinished: () -> Unit) {
    val controller = LocalController.current
    // Not saveable: a pending permission callback does not survive recreation either.
    var requesting by remember { mutableStateOf(false) }
    OnboardingScreen(
        requesting = requesting,
        onAllow = {
            requesting = true
            controller.platform.requestVpnPermission {
                controller.platform.requestNotificationPermission {
                    requesting = false
                    onFinished()
                }
            }
        },
        onLater = onFinished,
    )
}

@Composable
fun OnboardingScreen(
    onAllow: () -> Unit,
    onLater: () -> Unit,
    modifier: Modifier = Modifier,
    requesting: Boolean = false,
) {
    val c = ZeroTheme.colors
    Column(
        modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
            .windowInsetsPadding(WindowInsets.navigationBars),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            Modifier
                .weight(1f)
                .widthIn(max = 480.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 28.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(R.string.onboarding_perm_title),
                style = MaterialTheme.typography.headlineSmall,
                color = c.text,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.onboarding_perm_text),
                style = MaterialTheme.typography.bodyLarge,
                color = c.muted,
            )
        }
        Column(
            Modifier
                .widthIn(max = 480.dp)
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            PrimaryButton(stringResource(R.string.onboarding_allow), onAllow, Modifier.fillMaxWidth(), loading = requesting)
            TonalButton(stringResource(R.string.onboarding_later), onLater, Modifier.fillMaxWidth(), container = Color.Transparent, tint = c.muted, enabled = !requesting)
        }
    }
}
