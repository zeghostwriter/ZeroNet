package com.zeronet.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Countries

/**
 * A round badge with a country's flag. Devices whose fonts cannot draw flag
 * emoji (and unknown countries) get the two-letter code or a globe instead of
 * two boxed regional-indicator letters.
 */
@Composable
fun FlagBadge(country: String, modifier: Modifier = Modifier, size: Dp = 40.dp) {
    val c = ZeroTheme.colors
    val flag = remember(country) { Countries.flag(country) }
    val drawable = remember(flag) { Countries.canDraw(flag) }
    Box(
        modifier.size(size).clip(CircleShape).background(c.surfaceHi),
        contentAlignment = Alignment.Center,
    ) {
        when {
            drawable -> Text(
                flag,
                style = TextStyle(fontSize = (size.value * 0.52f).sp, textAlign = TextAlign.Center),
            )
            country.length == 2 -> Text(
                country.uppercase(),
                style = MaterialTheme.typography.labelMedium.copy(fontSize = (size.value * 0.3f).sp),
                color = c.text,
            )
            else -> Icon(ZeroIcons.Globe, null, tint = c.muted, modifier = Modifier.size(size * 0.5f))
        }
    }
}

/** A round badge with an icon (used for "Fastest"). */
@Composable
fun IconBadge(icon: ImageVector, modifier: Modifier = Modifier, size: Dp = 40.dp, tint: androidx.compose.ui.graphics.Color = ZeroTheme.colors.accent) {
    Box(
        modifier.size(size).clip(CircleShape).background(tint.copy(alpha = 0.16f)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, null, tint = tint, modifier = Modifier.size(size * 0.5f))
    }
}
