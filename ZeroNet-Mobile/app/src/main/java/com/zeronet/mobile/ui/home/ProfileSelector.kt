package com.zeronet.mobile.ui.home

import android.view.HapticFeedbackConstants
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ClipOp
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme

private val CardShape = RoundedCornerShape(18.dp)

/** Normal / Fast / Gaming, with one line under it saying what the choice does. */
@Composable
fun ProfileSelector(
    selected: ConnectionProfile,
    onSelect: (ConnectionProfile) -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = ZeroTheme.colors
    Column(modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(
            Modifier.fillMaxWidth().selectableGroup(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            ConnectionProfile.entries.forEach { p ->
                ProfileCard(
                    profile = p,
                    selected = p == selected,
                    onClick = { onSelect(p) },
                    modifier = Modifier.weight(1f),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        val reduced = LocalReducedMotion.current
        AnimatedContent(
            targetState = selected,
            transitionSpec = {
                fadeIn(tween(ZeroMotion.ms(if (reduced) 150 else 220))) togetherWith fadeOut(tween(ZeroMotion.ms(if (reduced) 150 else 120)))
            },
            label = "profileHint",
        ) { p ->
            Text(
                stringResource(p.hint()),
                style = MaterialTheme.typography.bodySmall,
                color = c.muted,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            )
        }
    }
}

@Composable
private fun ProfileCard(
    profile: ConnectionProfile,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier,
) {
    val c = ZeroTheme.colors
    val reduced = LocalReducedMotion.current
    val view = LocalView.current
    val gamingLive = selected && profile == ConnectionProfile.Gaming
    val clock = rememberAmbientClock(gamingLive && !reduced)

    val fill by animateColorAsState(
        if (selected) c.accent.copy(alpha = if (c.isDark) 0.14f else 0.12f) else c.surface,
        tween(ZeroMotion.ms(if (reduced) 150 else 260)),
        label = "profileFill",
    )
    val content by animateColorAsState(
        if (selected) c.accent else c.muted,
        tween(ZeroMotion.ms(if (reduced) 150 else 260)),
        label = "profileContent",
    )
    val press = remember { Animatable(1f) }
    val pop = remember { Animatable(1f) }
    LaunchedEffect(selected) {
        if (selected && !reduced) {
            pop.snapTo(0.92f)
            pop.animateTo(1f, ZeroMotion.expressive())
        }
    }
    val interaction = remember { MutableInteractionSource() }
    LaunchedEffect(interaction, reduced) {
        interaction.interactions.collect { i ->
            if (reduced) return@collect
            when (i) {
                is PressInteraction.Press -> press.animateTo(0.95f, ZeroMotion.snappy())
                is PressInteraction.Release, is PressInteraction.Cancel -> press.animateTo(1f, ZeroMotion.expressive())
            }
        }
    }

    Column(
        modifier
            .heightIn(min = 72.dp)
            .graphicsLayer {
                val s = press.value * pop.value
                scaleX = s; scaleY = s
            }
            .clip(CardShape)
            .background(fill)
            .then(
                if (gamingLive) {
                    // A neon edge that chases itself around the card.
                    Modifier.drawWithCache {
                        val stroke = Stroke(2.dp.toPx())
                        val corner = CornerRadius(18.dp.toPx())
                        val brush = Brush.sweepGradient(
                            0f to c.accentHot,
                            0.33f to c.accent,
                            0.66f to c.accentBright,
                            1f to c.accentHot,
                        )
                        onDrawWithContent {
                            drawContent()
                            val angle = if (reduced) 0f else clock.floatValue / 8f
                            // Rotating a sweep gradient inside the rounded rect's outline.
                            val path = androidx.compose.ui.graphics.Path().apply {
                                addRoundRect(
                                    androidx.compose.ui.geometry.RoundRect(
                                        left = stroke.width / 2f,
                                        top = stroke.width / 2f,
                                        right = size.width - stroke.width / 2f,
                                        bottom = size.height - stroke.width / 2f,
                                        cornerRadius = corner,
                                    ),
                                )
                            }
                            clipPath(path, clipOp = ClipOp.Intersect) {
                                rotate(angle) {
                                    drawCircle(brush, radius = size.maxDimension, center = center, style = Stroke(stroke.width * 2f))
                                }
                            }
                            drawPath(path, Color.White.copy(alpha = 0.06f), style = stroke)
                        }
                    }
                } else {
                    Modifier.border(
                        if (selected) 1.5.dp else 1.dp,
                        if (selected) c.accent else c.hairline,
                        CardShape,
                    )
                },
            )
            .selectable(
                selected = selected,
                interactionSource = interaction,
                indication = null,
                role = Role.RadioButton,
                onClick = {
                    if (!selected) view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
                    onClick()
                },
            )
            .padding(vertical = 12.dp, horizontal = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(profile.icon(), null, tint = content, modifier = Modifier.size(22.dp))
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(profile.label()),
            style = MaterialTheme.typography.labelLarge.copy(fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium),
            color = if (selected) c.text else c.muted,
            maxLines = 1,
        )
    }
}

private fun ConnectionProfile.icon(): ImageVector = when (this) {
    ConnectionProfile.Normal -> ZeroIcons.Shield
    ConnectionProfile.Fast -> ZeroIcons.Bolt
    ConnectionProfile.Gaming -> ZeroIcons.Gamepad
}

private fun ConnectionProfile.label(): Int = when (this) {
    ConnectionProfile.Normal -> R.string.profile_normal
    ConnectionProfile.Fast -> R.string.profile_fast
    ConnectionProfile.Gaming -> R.string.profile_gaming
}

private fun ConnectionProfile.hint(): Int = when (this) {
    ConnectionProfile.Normal -> R.string.profile_normal_hint
    ConnectionProfile.Fast -> R.string.profile_fast_hint
    ConnectionProfile.Gaming -> R.string.profile_gaming_hint
}
