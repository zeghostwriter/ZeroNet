package com.zeronet.mobile.ui.servers

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.WarpPhase
import com.zeronet.mobile.model.WarpState
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.effects.CipherKey
import com.zeronet.mobile.ui.effects.GlyphBadge
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import kotlinx.coroutines.delay
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.ltr

/** The shape the churn takes before the key is known: eight groups of four. */
private const val KEY_SHAPE = "0000 0000 0000 0000 0000 0000 0000 0000"

/**
 * Getting a Cloudflare WARP account. The keys are made on the phone; the row
 * of cipher text churns while the account is made and settles into the
 * fingerprint of the new keys once it exists.
 */
@Composable
fun WarpSheet(
    visible: Boolean,
    state: WarpState,
    onStart: () -> Unit,
    onCancel: () -> Unit,
    onDismiss: () -> Unit,
) {
    val title = stringResource(R.string.warp_title)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge, color = c.text, modifier = Modifier.semantics { heading() })
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(
                    when (state.phase) {
                        WarpPhase.Idle -> R.string.warp_body
                        WarpPhase.Working -> R.string.warp_working
                        WarpPhase.Done -> R.string.warp_done
                        WarpPhase.Failed -> R.string.warp_failed
                    },
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Spacer(Modifier.height(20.dp))
            if (state.phase == WarpPhase.Working || state.phase == WarpPhase.Done) {
                CipherKey(
                    target = state.fingerprint.takeIf { state.phase == WarpPhase.Done && it.isNotBlank() },
                    placeholder = KEY_SHAPE,
                    description = stringResource(R.string.warp_key_description),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.warp_fingerprint_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.muted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
                // Once the key has settled, its picture appears: the same one that marks the account in the list.
                var showGlyph by remember { mutableStateOf(false) }
                val reduced = LocalReducedMotion.current
                LaunchedEffect(state.phase, state.fingerprint) {
                    if (state.phase == WarpPhase.Done && state.fingerprint.isNotBlank()) {
                        if (!reduced) delay(2300)
                        showGlyph = true
                    } else {
                        showGlyph = false
                    }
                }
                AnimatedVisibility(
                    showGlyph,
                    enter = fadeIn(tween(ZeroMotion.ms(400))) + scaleIn(ZeroMotion.expressive(), initialScale = 0.6f),
                ) {
                    Box(Modifier.fillMaxWidth().padding(top = 14.dp), contentAlignment = Alignment.Center) {
                        GlyphBadge(state.fingerprint, size = 64.dp)
                    }
                }
                Spacer(Modifier.height(20.dp))
            }
            if (state.phase == WarpPhase.Done && state.servers > 0) {
                Text(
                    stringResource(R.string.warp_servers_found, state.servers),
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.text,
                )
                Spacer(Modifier.height(16.dp))
            }
            if (state.phase == WarpPhase.Failed && state.error.isNotBlank()) {
                Text(ltr(state.error), style = MaterialTheme.typography.bodySmall, color = c.muted)
                Spacer(Modifier.height(16.dp))
            }
            when (state.phase) {
                WarpPhase.Idle -> {
                    Text(stringResource(R.string.warp_terms), style = MaterialTheme.typography.bodySmall, color = c.muted)
                    Spacer(Modifier.height(16.dp))
                    PrimaryButton(stringResource(R.string.warp_get), onStart, Modifier.fillMaxWidth())
                }
                WarpPhase.Working -> TonalButton(stringResource(R.string.warp_cancel), onCancel, Modifier.fillMaxWidth())
                WarpPhase.Done -> PrimaryButton(stringResource(R.string.warp_finish), onDismiss, Modifier.fillMaxWidth())
                WarpPhase.Failed -> PrimaryButton(stringResource(R.string.warp_retry), onStart, Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
