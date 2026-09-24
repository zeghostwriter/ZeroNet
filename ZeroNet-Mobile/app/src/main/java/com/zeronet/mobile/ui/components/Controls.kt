package com.zeronet.mobile.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.Motion
import com.zeronet.mobile.ui.theme.ZeroTheme

// ------------------------------------------------------------------ surfaces

val CardShape = RoundedCornerShape(24.dp)
val RowShape = RoundedCornerShape(16.dp)

/** An opaque content card. Cards never use glass: text on them must stay AA. */
@Composable
fun ZeroCard(
    modifier: Modifier = Modifier,
    padding: PaddingValues = PaddingValues(16.dp),
    onClick: (() -> Unit)? = null,
    onClickLabel: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = ZeroTheme.colors
    var m = modifier
        .clip(CardShape)
        .background(c.surface)
        .border(1.dp, c.hairline, CardShape)
    if (onClick != null) {
        val interaction = remember { MutableInteractionSource() }
        m = modifier
            .pressScale(interaction)
            .clip(CardShape)
            .background(c.surface)
            .border(1.dp, c.hairline, CardShape)
            .clickable(
                interactionSource = interaction,
                indication = androidx.compose.material3.ripple(),
                onClickLabel = onClickLabel,
                role = Role.Button,
                onClick = onClick,
            )
    }
    Column(m.padding(padding), content = content)
}

/** A subtle scale-down while pressed, on a spring (skipped under reduced motion). */
@Composable
fun Modifier.pressScale(interaction: MutableInteractionSource? = null, pressed: Float = 0.98f): Modifier {
    if (interaction == null) return this
    val isPressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (isPressed) pressed else 1f, Motion.snappy(), label = "press")
    return graphicsLayer { scaleX = scale; scaleY = scale }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = ZeroTheme.colors.muted,
        modifier = modifier.semantics { heading() }.padding(horizontal = 4.dp, vertical = 8.dp),
    )
}

// ------------------------------------------------------------------ buttons

@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
    container: Color = ZeroTheme.colors.accent,
    content: Color = ZeroTheme.colors.onAccent,
) {
    val interaction = remember { MutableInteractionSource() }
    val c = ZeroTheme.colors
    Row(
        modifier = modifier
            .heightIn(min = 52.dp)
            .pressScale(interaction, 0.97f)
            .clip(CircleShape)
            .background(if (enabled) container else c.surfaceHi)
            .clickable(interactionSource = interaction, indication = androidx.compose.material3.ripple(), enabled = enabled && !loading, role = Role.Button, onClick = onClick)
            .padding(horizontal = 24.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val fg = if (enabled) content else c.muted
        if (loading) {
            CircularProgressIndicator(Modifier.size(18.dp), color = fg, strokeWidth = 2.dp)
            Spacer(Modifier.width(10.dp))
        } else if (icon != null) {
            Icon(icon, null, tint = fg, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.labelLarge, color = fg, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
fun TonalButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    tint: Color = ZeroTheme.colors.text,
    container: Color = ZeroTheme.colors.surfaceHi,
) {
    val interaction = remember { MutableInteractionSource() }
    Row(
        modifier = modifier
            .heightIn(min = 48.dp)
            .pressScale(interaction, 0.97f)
            .clip(CircleShape)
            .background(container)
            .clickable(interactionSource = interaction, indication = androidx.compose.material3.ripple(), enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val fg = if (enabled) tint else ZeroTheme.colors.muted
        if (icon != null) {
            Icon(icon, null, tint = fg, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.labelLarge, color = fg, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

/** A 48 dp round icon button (the touch target), with a smaller visual. */
@Composable
fun IconAction(
    icon: ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    tint: Color = ZeroTheme.colors.text,
    container: Color = Color.Transparent,
    enabled: Boolean = true,
    size: Dp = 48.dp,
    iconSize: Dp = 22.dp,
) {
    val interaction = remember { MutableInteractionSource() }
    Box(
        modifier = modifier
            .size(size)
            .pressScale(interaction, 0.9f)
            .clip(CircleShape)
            .background(container)
            .clickable(interactionSource = interaction, indication = androidx.compose.material3.ripple(bounded = true), enabled = enabled, role = Role.Button, onClick = onClick)
            .semantics { this.contentDescription = contentDescription },
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, null, tint = if (enabled) tint else ZeroTheme.colors.muted, modifier = Modifier.size(iconSize))
    }
}

// ------------------------------------------------------------------ chips

@Composable
fun ZeroChip(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    selected: Boolean = false,
    icon: ImageVector? = null,
    trailing: ImageVector? = null,
    tint: Color? = null,
) {
    val c = ZeroTheme.colors
    val bg by animateColorAsState(if (selected) c.accent else c.surfaceHi, Motion.snappy(), label = "chipBg")
    val fg = when {
        selected -> c.onAccent
        tint != null -> tint
        else -> c.text
    }
    val interaction = remember { MutableInteractionSource() }
    Row(
        modifier = modifier
            .heightIn(min = 40.dp)
            .pressScale(interaction, 0.95f)
            .clip(CircleShape)
            .background(bg)
            .clickable(interactionSource = interaction, indication = androidx.compose.material3.ripple(), role = Role.Button, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Icon(icon, null, tint = fg, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
        }
        Text(text, style = MaterialTheme.typography.labelLarge, color = fg, maxLines = 1, overflow = TextOverflow.Ellipsis)
        if (trailing != null) {
            Spacer(Modifier.width(6.dp))
            Icon(trailing, null, tint = fg, modifier = Modifier.size(16.dp))
        }
    }
}

/** A small, quiet label ("Direct", "CDN"). */
@Composable
fun Badge(text: String, color: Color, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        maxLines = 1,
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    )
}

// ------------------------------------------------------------------ segmented

/**
 * A segmented control with a sliding pill. The pill's position is animated
 * and read only while drawing, so switching does not recompose the row.
 */
@Composable
fun <T> Segmented(
    options: List<T>,
    selected: T,
    onSelect: (T) -> Unit,
    label: @Composable (T) -> String,
    modifier: Modifier = Modifier,
) {
    val c = ZeroTheme.colors
    val index = options.indexOf(selected).coerceAtLeast(0)
    val pos = remember { Animatable(index.toFloat()) }
    val spec = Motion.expressive<Float>()
    LaunchedEffect(index) { pos.animateTo(index.toFloat(), spec) }
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Box(
        modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(CircleShape)
            .background(c.surfaceHi)
            .padding(4.dp),
    ) {
        val n = options.size.coerceAtLeast(1)
        Box(
            Modifier
                .matchParentSize()
                .drawBehind {
                    val w = size.width / n
                    val x = if (rtl) size.width - w * (pos.value + 1) else w * pos.value
                    drawRoundRect(
                        color = c.surface,
                        topLeft = Offset(x, 0f),
                        size = Size(w, size.height),
                        cornerRadius = CornerRadius(size.height / 2, size.height / 2),
                    )
                    drawRoundRect(
                        color = c.border.copy(alpha = 0.6f),
                        topLeft = Offset(x, 0f),
                        size = Size(w, size.height),
                        cornerRadius = CornerRadius(size.height / 2, size.height / 2),
                        style = androidx.compose.ui.graphics.drawscope.Stroke(1.dp.toPx()),
                    )
                },
        )
        Row(Modifier.fillMaxWidth().selectableGroup()) {
            options.forEachIndexed { i, option ->
                val isSel = i == index
                val fg by animateColorAsState(if (isSel) c.text else c.muted, Motion.snappy(), label = "segFg")
                Box(
                    Modifier
                        .weight(1f)
                        .heightIn(min = 40.dp)
                        .clip(CircleShape)
                        .selectable(selected = isSel, role = Role.Tab, onClick = { if (!isSel) onSelect(option) })
                        .padding(horizontal = 8.dp, vertical = 8.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        label(option),
                        style = MaterialTheme.typography.labelLarge,
                        color = fg,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

// ------------------------------------------------------------------ rows

@Composable
fun ToggleRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    enabled: Boolean = true,
) {
    val c = ZeroTheme.colors
    Row(
        modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clip(RowShape)
            .toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onCheckedChange)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = if (enabled) c.text else c.muted)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.muted)
        }
        Spacer(Modifier.width(16.dp))
        Switch(
            checked = checked,
            onCheckedChange = null,
            enabled = enabled,
            colors = SwitchDefaults.colors(
                checkedThumbColor = c.onAccent,
                checkedTrackColor = c.accent,
                checkedBorderColor = c.accent,
                uncheckedThumbColor = c.muted,
                uncheckedTrackColor = c.surfaceHi,
                uncheckedBorderColor = c.border,
            ),
        )
    }
}

/** A row that opens something: title, current value, chevron. */
@Composable
fun NavRow(
    title: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    value: String? = null,
    subtitle: String? = null,
    icon: ImageVector? = null,
    trailingIcon: ImageVector = ZeroIcons.ChevronEnd,
    tint: Color = ZeroTheme.colors.text,
) {
    val c = ZeroTheme.colors
    Row(
        modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clip(RowShape)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(14.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = tint)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.muted)
        }
        if (value != null) {
            Spacer(Modifier.width(12.dp))
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(0.6f, fill = false),
            )
        }
        Spacer(Modifier.width(4.dp))
        Icon(trailingIcon, null, tint = c.muted, modifier = Modifier.size(20.dp))
    }
}

/** A labelled control stacked vertically (title above a segmented control or chips). */
@Composable
fun LabeledBlock(title: String, modifier: Modifier = Modifier, subtitle: String? = null, content: @Composable ColumnScope.() -> Unit) {
    val c = ZeroTheme.colors
    Column(modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(title, style = MaterialTheme.typography.bodyLarge, color = c.text)
        if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.muted)
        Spacer(Modifier.height(10.dp))
        content()
    }
}

@Composable
fun Hairline(modifier: Modifier = Modifier) {
    Box(modifier.fillMaxWidth().height(1.dp).background(ZeroTheme.colors.hairline))
}

// ------------------------------------------------------------------ text fields

@Composable
fun ZeroTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "",
    leading: ImageVector? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    maxLines: Int = if (singleLine) 1 else 8,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: ImeAction = ImeAction.Done,
    onImeAction: (() -> Unit)? = null,
    clearLabel: String? = null,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    textStyle: TextStyle = MaterialTheme.typography.bodyLarge,
) {
    val c = ZeroTheme.colors
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        singleLine = singleLine,
        minLines = minLines,
        maxLines = maxLines,
        textStyle = textStyle.copy(color = c.text),
        cursorBrush = SolidColor(c.accent),
        visualTransformation = visualTransformation,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onAny = { onImeAction?.invoke() }),
        modifier = modifier.fillMaxWidth(),
        decorationBox = { inner ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp)
                    .clip(RowShape)
                    .background(c.surfaceHi)
                    .border(BorderStroke(1.dp, c.hairline), RowShape)
                    .padding(start = if (leading != null) 12.dp else 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                verticalAlignment = if (singleLine) Alignment.CenterVertically else Alignment.Top,
            ) {
                if (leading != null) {
                    Icon(leading, null, tint = c.muted, modifier = Modifier.padding(top = if (singleLine) 0.dp else 12.dp).size(20.dp))
                    Spacer(Modifier.width(10.dp))
                }
                Box(Modifier.weight(1f).padding(vertical = if (singleLine) 0.dp else 10.dp)) {
                    if (value.isEmpty()) {
                        Text(placeholder, style = textStyle, color = c.muted, maxLines = if (singleLine) 1 else 4, overflow = TextOverflow.Ellipsis)
                    }
                    inner()
                }
                if (clearLabel != null && value.isNotEmpty()) {
                    IconAction(ZeroIcons.Close, clearLabel, onClick = { onValueChange("") }, tint = c.muted, size = 44.dp, iconSize = 18.dp)
                } else {
                    Spacer(Modifier.width(12.dp))
                }
            }
        },
    )
}

// ------------------------------------------------------------------ misc

/** Four bars that fill with signal quality; the colour follows the delay. */
@Composable
fun PingBars(delayMs: Int, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val level = when {
        delayMs < 0 -> 0
        delayMs < 250 -> 4
        delayMs < 500 -> 3
        delayMs < 900 -> 2
        else -> 1
    }
    val on = c.delayColor(delayMs)
    val off = c.border
    Box(
        modifier.size(width = 18.dp, height = 14.dp).drawBehind {
            val bw = size.width / 4f * 0.62f
            val gap = (size.width - bw * 4) / 3f
            for (i in 0 until 4) {
                val h = size.height * (0.35f + 0.65f * (i + 1) / 4f)
                drawRoundRect(
                    color = if (i < level) on else off,
                    topLeft = Offset(i * (bw + gap), size.height - h),
                    size = Size(bw, h),
                    cornerRadius = CornerRadius(bw / 2, bw / 2),
                )
            }
        },
    )
}

/** Tints children with [color] through LocalContentColor. */
@Composable
fun WithContentColor(color: Color, content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalContentColor provides color, content = content)
}

@Composable
fun RowScope.Grow() = Spacer(Modifier.weight(1f))

@Composable
fun VerticalGap(height: Dp) = Spacer(Modifier.height(height))

@Composable
fun ProgressRing(progress: () -> Float, modifier: Modifier = Modifier, color: Color = ZeroTheme.colors.accent, track: Color = ZeroTheme.colors.border, stroke: Dp = 3.dp) {
    Box(
        modifier.drawBehind {
            val s = stroke.toPx()
            val inset = s / 2
            val arcSize = Size(size.width - s, size.height - s)
            drawArc(track, 0f, 360f, false, Offset(inset, inset), arcSize, style = androidx.compose.ui.graphics.drawscope.Stroke(s))
            drawArc(
                color, -90f, 360f * progress().coerceIn(0f, 1f), false, Offset(inset, inset), arcSize,
                style = androidx.compose.ui.graphics.drawscope.Stroke(s, cap = androidx.compose.ui.graphics.StrokeCap.Round),
            )
        },
    )
}

@Composable
fun FillHeight(modifier: Modifier = Modifier) = Spacer(modifier.fillMaxHeight())

@Composable
fun MinTouch(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(modifier.defaultMinSize(48.dp, 48.dp), contentAlignment = Alignment.Center) { content() }
}
