package com.zeronet.mobile.ui.settings

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.CheckStatus
import com.zeronet.mobile.model.DiagCheck
import com.zeronet.mobile.model.Diagnosis
import com.zeronet.mobile.service.Diagnostics
import com.zeronet.mobile.service.EngineLog
import com.zeronet.mobile.ui.components.Hairline
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ------------------------------------------------------------------ self-test

/** "Test my connection": what the network blocks and which kinds of server get through. */
@Composable
fun DiagnosticsSheet(visible: Boolean, diagnosis: Diagnosis, onRun: () -> Unit, onLogs: () -> Unit, onDismiss: () -> Unit) {
    val title = stringResource(R.string.diag_title)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        SheetHeader(title, stringResource(R.string.diag_body))
        SheetBody {
            if (diagnosis.checks.isEmpty()) {
                Text(stringResource(R.string.diag_not_run), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.muted, modifier = Modifier.padding(vertical = 12.dp))
            }
            diagnosis.checks.forEachIndexed { i, check ->
                if (i > 0) Hairline()
                CheckRow(check)
            }
            if (!diagnosis.running && diagnosis.checks.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text(verdict(diagnosis.checks), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.text)
            }
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PrimaryButton(
                    stringResource(if (diagnosis.checks.isEmpty()) R.string.diag_run else R.string.diag_run_again),
                    onRun,
                    loading = diagnosis.running,
                    enabled = !diagnosis.running,
                    icon = ZeroIcons.Signal,
                    modifier = Modifier.weight(1f),
                )
                TonalButton(stringResource(R.string.logs_title), onLogs, icon = ZeroIcons.Info)
            }
        }
    }
}

@Composable
private fun CheckRow(check: DiagCheck) {
    val c = ZeroTheme.colors
    val name = checkName(check.id)
    val state = statusText(check.status)
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(vertical = 8.dp)
            .semantics(mergeDescendants = true) { contentDescription = "$name, $state, ${check.detail}" },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(22.dp), contentAlignment = Alignment.Center) {
            if (check.status == CheckStatus.Running) {
                CircularProgressIndicator(Modifier.size(18.dp), color = c.accent, strokeWidth = 2.dp)
            } else {
                Box(Modifier.size(12.dp).clip(CircleShape).background(statusColor(check.status)))
            }
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, color = c.text)
            val detail = check.detail.ifBlank { state }
            // Findings are technical (addresses, errors): always left to right.
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr),
                color = if (check.status == CheckStatus.Bad) c.err else c.muted,
            )
        }
    }
}

@Composable
private fun statusColor(status: CheckStatus): Color {
    val c = ZeroTheme.colors
    return when (status) {
        CheckStatus.Ok -> c.ok
        CheckStatus.Warn -> c.warn
        CheckStatus.Bad -> c.err
        CheckStatus.Running -> c.accent
        CheckStatus.Pending, CheckStatus.Skipped -> c.border
    }
}

@Composable
private fun statusText(status: CheckStatus): String = stringResource(
    when (status) {
        CheckStatus.Pending -> R.string.diag_status_pending
        CheckStatus.Running -> R.string.diag_status_running
        CheckStatus.Ok -> R.string.diag_status_ok
        CheckStatus.Warn -> R.string.diag_status_warn
        CheckStatus.Bad -> R.string.diag_status_bad
        CheckStatus.Skipped -> R.string.diag_status_skipped
    },
)

@Composable
private fun checkName(id: String): String = when (id) {
    Diagnostics.NETWORK -> stringResource(R.string.diag_network)
    Diagnostics.INTERNET -> stringResource(R.string.diag_internet)
    Diagnostics.DNS -> stringResource(R.string.diag_dns)
    Diagnostics.TLS -> stringResource(R.string.diag_tls)
    Diagnostics.TUNNEL -> stringResource(R.string.diag_tunnel)
    else -> stringResource(R.string.diag_family, familyLabel(id))
}

/** The server-kind badge text for a `family_<kind>` check. */
@Composable
private fun familyLabel(id: String): String = when (id.removePrefix(Diagnostics.FAMILY_PREFIX)) {
    "split" -> stringResource(R.string.kind_split)
    "direct" -> stringResource(R.string.kind_direct)
    "cdn" -> stringResource(R.string.kind_cdn)
    "quic" -> stringResource(R.string.kind_quic)
    "other" -> stringResource(R.string.kind_other)
    else -> id
}

/** One sentence that says what the findings mean for the user. */
@Composable
private fun verdict(checks: List<DiagCheck>): String {
    fun status(id: String) = checks.firstOrNull { it.id == id }?.status
    val families = checks.filter { it.id.startsWith(Diagnostics.FAMILY_PREFIX) }
    val working = families.filter { it.status == CheckStatus.Ok || it.status == CheckStatus.Warn }
    return when {
        status(Diagnostics.NETWORK) == CheckStatus.Bad -> stringResource(R.string.diag_verdict_offline)
        status(Diagnostics.INTERNET) == CheckStatus.Bad && working.isEmpty() -> stringResource(R.string.diag_verdict_no_internet)
        working.isNotEmpty() -> stringResource(
            R.string.diag_verdict_families,
            working.map { familyLabel(it.id) }.joinToString(if (isRtl()) "، " else ", "),
        )
        families.all { it.status == CheckStatus.Skipped } -> stringResource(R.string.diag_verdict_no_servers)
        else -> stringResource(R.string.diag_verdict_none_work)
    }
}

@Composable
private fun isRtl(): Boolean = androidx.compose.ui.platform.LocalLayoutDirection.current == androidx.compose.ui.unit.LayoutDirection.Rtl

// ------------------------------------------------------------------ logs

private enum class LogSource { Connection, Core }

/**
 * What the engine did (the connection log) and what the core reported (its
 * own log), newest at the bottom, to copy or share with whoever helps.
 */
@Composable
fun LogsSheet(visible: Boolean, detailed: Boolean, onDismiss: () -> Unit, onCopy: (String) -> Unit) {
    val title = stringResource(R.string.logs_title)
    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val c = ZeroTheme.colors
        val context = LocalContext.current
        val scope = rememberCoroutineScope()
        var source by rememberSaveable { androidx.compose.runtime.mutableStateOf(LogSource.Connection) }
        var generation by remember { mutableIntStateOf(0) }
        val text by produceState("", visible, source, generation) {
            if (!visible) return@produceState
            value = withContext(Dispatchers.IO) {
                EngineLog.tail(context.filesDir, if (source == LogSource.Connection) EngineLog.FILE else EngineLog.CORE_FILE)
            }
        }
        SheetHeader(title, stringResource(if (detailed) R.string.logs_body_detailed else R.string.logs_body))
        Column(Modifier.padding(horizontal = 24.dp)) {
            Segmented(
                LogSource.entries, source, { source = it },
                label = { stringResource(if (it == LogSource.Connection) R.string.logs_connection else R.string.logs_core) },
            )
            Spacer(Modifier.height(12.dp))
        }
        SheetBody {
            val lines = text.trimEnd()
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(c.surfaceHi)
                    .horizontalScroll(rememberScrollState())
                    .padding(12.dp),
            ) {
                SelectionContainer {
                    Text(
                        lines.ifEmpty { stringResource(R.string.logs_empty) },
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp, textDirection = TextDirection.Ltr),
                        color = if (lines.isEmpty()) c.muted else c.text,
                        softWrap = false,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(stringResource(R.string.logs_refresh), { generation++ }, icon = ZeroIcons.Refresh)
                TonalButton(stringResource(R.string.logs_copy), { onCopy(lines) }, icon = ZeroIcons.Copy, enabled = lines.isNotEmpty())
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(
                    stringResource(R.string.logs_share),
                    {
                        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                            .putExtra(Intent.EXTRA_SUBJECT, "ZeroNet log")
                            .putExtra(Intent.EXTRA_TEXT, lines.takeLast(200_000))
                        runCatching { context.startActivity(Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                    },
                    icon = ZeroIcons.Share,
                    enabled = lines.isNotEmpty(),
                )
                TonalButton(
                    stringResource(R.string.logs_clear),
                    {
                        scope.launch {
                            withContext(Dispatchers.IO) { EngineLog.clear(context.filesDir) }
                            generation++
                        }
                    },
                    icon = ZeroIcons.Trash,
                    tint = c.err,
                )
            }
        }
    }
}
