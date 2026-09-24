package com.zeronet.mobile.ui.servers

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.data.Subscription
import com.zeronet.mobile.model.ImportResult
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.ui.components.Badge
import com.zeronet.mobile.ui.components.FlagBadge
import com.zeronet.mobile.ui.components.Hairline
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.QrCode
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.model.countryLabel
import com.zeronet.mobile.ui.model.kindLabel
import com.zeronet.mobile.ui.model.protocolLabel
import com.zeronet.mobile.ui.model.securityLabel
import com.zeronet.mobile.ui.model.serverTitle
import com.zeronet.mobile.ui.model.sourceLabel
import com.zeronet.mobile.ui.model.transportLabel
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import com.zeronet.mobile.ui.theme.ZeroMotion
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.Num
import com.zeronet.mobile.ui.util.currentLocale
import com.zeronet.mobile.ui.util.formatAgo
import com.zeronet.mobile.ui.util.formatDelay
import kotlinx.coroutines.launch

@Composable
fun ServerDetailSheet(
    server: Server?,
    subscriptions: List<Subscription>,
    testing: Boolean,
    now: Long,
    onConnect: (Server) -> Unit,
    onTest: (Server) -> Unit,
    onCopyLink: (Server) -> Unit,
    onFavorite: (Server, Boolean) -> Unit,
    onDelete: (Server) -> Unit,
    onDismiss: () -> Unit,
    initiallySharing: Boolean = false,
) {
    // Keep the last server while the sheet animates out.
    var shown by remember { mutableStateOf(server) }
    if (server != null) shown = server
    val s = shown
    ZeroSheet(visible = server != null, onDismiss = onDismiss, title = s?.let { serverTitle(LocalContext.current, it, currentLocale()) } ?: "") {
        if (s != null) {
            DetailContent(s, subscriptions, testing, now, onConnect, onTest, onCopyLink, onFavorite, onDelete, initiallySharing)
        }
    }
}

@Composable
private fun ColumnScope.DetailContent(
    s: Server,
    subscriptions: List<Subscription>,
    testing: Boolean,
    now: Long,
    onConnect: (Server) -> Unit,
    onTest: (Server) -> Unit,
    onCopyLink: (Server) -> Unit,
    onFavorite: (Server, Boolean) -> Unit,
    onDelete: (Server) -> Unit,
    initiallySharing: Boolean,
) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val locale = currentLocale()
    var sharing by rememberSaveable(s.key) { mutableStateOf(initiallySharing) }
    var confirmDelete by rememberSaveable(s.key) { mutableStateOf(false) }
    val reduced = LocalReducedMotion.current
    // The flag lands with a small spring when the sheet opens.
    val flagScale = remember(s.key) { Animatable(if (reduced) 1f else 0.6f) }
    LaunchedEffect(s.key) { if (!reduced) flagScale.animateTo(1f, ZeroMotion.expressive()) }

    Column(
        Modifier
            .weight(1f, fill = false)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FlagBadge(s.country, size = 56.dp, modifier = Modifier.graphicsLayer { scaleX = flagScale.value; scaleY = flagScale.value })
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    serverTitle(context, s, locale),
                    style = MaterialTheme.typography.titleLarge,
                    color = c.text,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.semantics { heading() },
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(countryLabel(context, s.country, locale), style = MaterialTheme.typography.bodyMedium, color = c.muted)
                    Spacer(Modifier.width(8.dp))
                    Badge(kindLabel(context, s.kind), c.info)
                }
            }
            IconAction(
                if (s.favorite) ZeroIcons.StarFilled else ZeroIcons.Star,
                stringResource(if (s.favorite) R.string.action_unfavorite else R.string.action_favorite),
                onClick = { onFavorite(s, !s.favorite) },
                tint = if (s.favorite) c.accent else c.muted,
            )
        }
        Spacer(Modifier.height(20.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton(stringResource(R.string.action_connect), { onConnect(s) }, Modifier.weight(1f), icon = ZeroIcons.Bolt)
            TonalButton(
                stringResource(if (testing) R.string.detail_testing else R.string.action_test),
                { onTest(s) },
                Modifier.weight(1f).heightIn(min = 52.dp),
                icon = ZeroIcons.Refresh,
                enabled = !testing,
            )
        }
        Spacer(Modifier.height(20.dp))
        DetailRow(stringResource(R.string.detail_delay), formatDelay(context, s.delayMs, locale), c.delayColor(s.delayMs))
        Hairline()
        DetailRow(stringResource(R.string.detail_last_tested), formatAgo(context, s.lastTestedAt, now, locale))
        Hairline()
        DetailRow(stringResource(R.string.detail_protocol), protocolLabel(s.protocol))
        Hairline()
        DetailRow(stringResource(R.string.detail_transport), transportLabel(s.transport))
        Hairline()
        DetailRow(stringResource(R.string.detail_security), securityLabel(s.security))
        Hairline()
        DetailRow(stringResource(R.string.detail_address), if (s.port > 0) "${s.host}:${s.port}" else s.host, ltr = true)
        Hairline()
        DetailRow(stringResource(R.string.detail_source), sourceLabel(context, s.source, subscriptions))
        if (s.aliveCount + s.failCount > 0) {
            Hairline()
            DetailRow(
                stringResource(R.string.detail_history),
                stringResource(R.string.detail_history_value, Num.int(s.aliveCount, locale), Num.int(s.aliveCount + s.failCount, locale)),
            )
        }
        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TonalButton(
                stringResource(if (sharing) R.string.action_hide_qr else R.string.action_share),
                { sharing = !sharing },
                Modifier.weight(1f),
                icon = ZeroIcons.Qr,
            )
            TonalButton(stringResource(R.string.action_copy_link), { onCopyLink(s) }, Modifier.weight(1f), icon = ZeroIcons.Copy)
        }
        AnimatedVisibility(sharing, enter = fadeIn() + expandVertically(), exit = fadeOut() + shrinkVertically()) {
            Column(Modifier.fillMaxWidth().padding(top = 16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                QrCode(s.link, stringResource(R.string.detail_qr_description), Modifier.widthIn(max = 260.dp).fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.detail_share_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.muted,
                    textAlign = TextAlign.Center,
                )
            }
        }
        if (s.isUser) {
            Spacer(Modifier.height(8.dp))
            if (!confirmDelete) {
                TonalButton(
                    stringResource(R.string.action_delete),
                    { confirmDelete = true },
                    Modifier.fillMaxWidth(),
                    icon = ZeroIcons.Trash,
                    tint = c.err,
                    container = c.err.copy(alpha = 0.10f),
                )
            } else {
                Text(stringResource(R.string.detail_delete_confirm), style = MaterialTheme.typography.bodyMedium, color = c.text, modifier = Modifier.padding(vertical = 8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TonalButton(stringResource(R.string.action_cancel), { confirmDelete = false }, Modifier.weight(1f))
                    PrimaryButton(stringResource(R.string.action_delete), { onDelete(s) }, Modifier.weight(1f), container = c.err, content = c.bg)
                }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun DetailRow(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color = ZeroTheme.colors.text, ltr: Boolean = false) {
    val c = ZeroTheme.colors
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = c.muted, modifier = Modifier.weight(0.42f))
        SelectionContainer(Modifier.weight(0.58f)) {
            Text(
                if (ltr) com.zeronet.mobile.ui.util.ltr(value) else value,
                style = MaterialTheme.typography.bodyMedium,
                color = valueColor,
                textAlign = TextAlign.End,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

enum class ImportMode { Links, Subscription }

/**
 * Add your own servers: paste links (or anything that contains them), or a
 * subscription URL the app refreshes itself.
 */
@Composable
fun ImportSheet(
    visible: Boolean,
    initialText: String?,
    onImport: suspend (String) -> ImportResult,
    onAddSubscription: (name: String, url: String) -> Unit,
    readClipboard: () -> String,
    onDismiss: () -> Unit,
) {
    val title = stringResource(R.string.import_title)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val locale = currentLocale()
        val scope = rememberCoroutineScope()
        var mode by rememberSaveable { mutableStateOf(ImportMode.Links) }
        var text by rememberSaveable { mutableStateOf("") }
        var subName by rememberSaveable { mutableStateOf("") }
        var subUrl by rememberSaveable { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        var result by remember { mutableStateOf<ImportResult?>(null) }
        var urlError by remember { mutableStateOf(false) }
        LaunchedEffect(initialText) {
            if (!initialText.isNullOrBlank()) {
                val t = initialText.trim()
                if (t.startsWith("http://") || t.startsWith("https://")) {
                    mode = ImportMode.Subscription
                    subUrl = t
                } else {
                    mode = ImportMode.Links
                    text = t
                }
                result = null
            }
        }
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge, color = c.text, modifier = Modifier.semantics { heading() })
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.import_body), style = MaterialTheme.typography.bodyMedium, color = c.muted)
            Spacer(Modifier.height(16.dp))
            Segmented(
                options = ImportMode.entries,
                selected = mode,
                onSelect = { mode = it; result = null },
                label = { stringResource(if (it == ImportMode.Links) R.string.import_links else R.string.import_subscription) },
            )
            Spacer(Modifier.height(16.dp))
            if (mode == ImportMode.Links) {
                ZeroTextField(
                    value = text,
                    onValueChange = { text = it; result = null },
                    placeholder = stringResource(R.string.import_links_placeholder),
                    singleLine = false,
                    minLines = 4,
                    maxLines = 8,
                    imeAction = ImeAction.Default,
                    clearLabel = stringResource(R.string.action_clear),
                    textStyle = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TonalButton(
                        stringResource(R.string.action_paste),
                        { text = readClipboard().trim(); result = null },
                        Modifier.weight(1f),
                        icon = ZeroIcons.Paste,
                    )
                    PrimaryButton(
                        stringResource(R.string.action_add),
                        {
                            busy = true
                            scope.launch {
                                result = onImport(text)
                                busy = false
                                if (result?.let { it.added > 0 && it.error == null } == true) text = ""
                            }
                        },
                        Modifier.weight(1f),
                        icon = ZeroIcons.Plus,
                        enabled = text.isNotBlank(),
                        loading = busy,
                    )
                }
                result?.let { r ->
                    Spacer(Modifier.height(12.dp))
                    val ok = r.error == null && r.added > 0
                    val msg = when {
                        r.error != null -> stringResource(R.string.import_error, r.error)
                        else -> stringResource(
                            R.string.import_result,
                            Num.int(r.added, locale),
                            Num.int(r.duplicates, locale),
                            Num.int(r.rejected, locale),
                        )
                    }
                    Text(msg, style = MaterialTheme.typography.bodyMedium, color = if (ok) c.ok else if (r.error != null) c.err else c.warn)
                }
            } else {
                ZeroTextField(
                    value = subUrl,
                    onValueChange = { subUrl = it.trim(); urlError = false },
                    placeholder = stringResource(R.string.import_sub_url),
                    leading = ZeroIcons.Link,
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Next,
                    clearLabel = stringResource(R.string.action_clear),
                )
                Spacer(Modifier.height(10.dp))
                ZeroTextField(
                    value = subName,
                    onValueChange = { subName = it },
                    placeholder = stringResource(R.string.import_sub_name),
                )
                if (urlError) {
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.import_sub_invalid), style = MaterialTheme.typography.bodySmall, color = c.err)
                }
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TonalButton(
                        stringResource(R.string.action_paste),
                        { subUrl = readClipboard().trim(); urlError = false },
                        Modifier.weight(1f),
                        icon = ZeroIcons.Paste,
                    )
                    PrimaryButton(
                        stringResource(R.string.action_add),
                        {
                            val url = subUrl.trim()
                            val valid = (url.startsWith("https://") || url.startsWith("http://")) && url.substringAfter("://").isNotBlank()
                            if (!valid) {
                                urlError = true
                            } else {
                                onAddSubscription(subName.trim().ifBlank { url.substringAfter("://").substringBefore('/') }, url)
                                subUrl = ""
                                subName = ""
                            }
                        },
                        Modifier.weight(1f),
                        icon = ZeroIcons.Plus,
                        enabled = subUrl.isNotBlank(),
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.import_sub_hint), style = MaterialTheme.typography.bodySmall, color = c.muted)
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}
