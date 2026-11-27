package com.zeronet.mobile.ui.servers

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.theme.ZeroTheme

/**
 * The one question about Cloudflare, asked once, before a connect.
 *
 * It sits in the way of the connect the person asked for, so it has to say the
 * two things that decide the answer: an account is registered with Cloudflare,
 * and a server is borrowed for the trip when Cloudflare cannot be reached from
 * here — then let go again. Agreeing stores the answer and lets the connect
 * carry on; declining does the same with "never".
 *
 * Dismissing it counts as declining, so backing out of a sheet is never read as
 * agreeing to register a device with a third party.
 */
@Composable
fun WarpConsentSheet(
    visible: Boolean,
    onAnswer: (agree: Boolean) -> Unit,
) {
    val title = stringResource(R.string.warp_consent_title)
    ZeroSheet(visible = visible, onDismiss = { onAnswer(false) }, title = title) {
        val c = ZeroTheme.colors
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleLarge,
                color = c.text,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.warp_consent_body),
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Spacer(Modifier.height(16.dp))
            Text(
                stringResource(R.string.warp_consent_borrow),
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
            )
            Spacer(Modifier.height(16.dp))
            Text(
                stringResource(R.string.warp_consent_terms) + "\n" +
                    stringResource(R.string.warp_consent_change),
                style = MaterialTheme.typography.bodySmall,
                color = c.muted,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Spacer(Modifier.height(20.dp))
            PrimaryButton(stringResource(R.string.warp_consent_agree), { onAnswer(true) }, Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.warp_consent_decline), { onAnswer(false) }, Modifier.fillMaxWidth())
            Spacer(Modifier.height(24.dp))
        }
    }
}