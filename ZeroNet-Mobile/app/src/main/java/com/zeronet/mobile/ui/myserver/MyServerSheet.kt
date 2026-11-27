package com.zeronet.mobile.ui.myserver

import android.content.Intent
import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.data.MyServerStore
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.QrCode
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import com.zeronet.mobile.ui.util.ltr

/**
 * The "My server" page: put in a server's address and password, and the app
 * installs everything on it, then shows the configs and who is connected.
 * It is a sheet over the Servers tab; [MyServerModel] holds all the state.
 */
@Composable
fun MyServerSheet(model: MyServerModel) {
    ZeroSheet(
        visible = model.open,
        onDismiss = model::back,
        title = stringResource(R.string.ms_title),
    ) {
        val c = ZeroTheme.colors
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            val screen = model.screen
            Text(
                titleFor(screen),
                style = MaterialTheme.typography.titleLarge,
                color = c.text,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(12.dp))
            when (screen) {
                MsScreen.List -> ListPage(model)
                MsScreen.Form -> FormPage(model)
                MsScreen.Busy -> Text(stringResource(R.string.ms_busy), color = c.muted, style = MaterialTheme.typography.bodyMedium)
                is MsScreen.Identity -> IdentityPage(model, screen)
                is MsScreen.Dns -> DnsPage(model, screen)
                is MsScreen.Progress -> ProgressPage(model, screen)
                is MsScreen.Result -> ResultPage(model, screen)
                is MsScreen.Server -> ServerPage(model, screen)
                is MsScreen.ConfirmRemove -> ConfirmPage(model, screen)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun titleFor(screen: MsScreen): String = stringResource(
    when (screen) {
        MsScreen.List -> R.string.ms_title
        MsScreen.Form -> R.string.ms_form_title
        MsScreen.Busy -> R.string.ms_busy_title
        is MsScreen.Identity -> R.string.ms_identity_title
        is MsScreen.Dns -> R.string.ms_dns_title
        is MsScreen.Progress -> R.string.ms_progress_title
        is MsScreen.Result -> R.string.ms_result_title
        is MsScreen.Server -> R.string.ms_server_title
        is MsScreen.ConfirmRemove -> R.string.ms_remove_title
    },
)

@Composable
private fun Body(text: String, muted: Boolean = false) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = if (muted) ZeroTheme.colors.muted else ZeroTheme.colors.text,
    )
}

@Composable
private fun Small(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
}

// ------------------------------------------------------------------- list

@Composable
private fun ListPage(model: MyServerModel) {
    val c = ZeroTheme.colors
    model.notice?.let {
        Text(it, style = MaterialTheme.typography.bodyMedium, color = c.accent, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        Spacer(Modifier.height(12.dp))
    }
    if (model.entries.isEmpty()) {
        Body(stringResource(R.string.ms_intro_1))
        Spacer(Modifier.height(8.dp))
        Body(stringResource(R.string.ms_intro_2), muted = true)
        Spacer(Modifier.height(8.dp))
        Small(stringResource(R.string.ms_privacy))
    } else {
        model.entries.forEach { entry ->
            val kinds = entry.kinds.map { serviceTitle(it) }
            val live = model.usage[entry.id]?.inbounds?.sumOf { it.now }
            NavRow(
                title = entry.name,
                subtitle = ltr(entry.host) + " · " + kinds.joinToString(" + "),
                value = live?.let { stringResource(R.string.ms_connected_count, it) },
                onClick = { model.openServer(entry.id) },
            )
        }
    }
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.ms_add), model::startAdd, Modifier.fillMaxWidth(), icon = ZeroIcons.Plus)
}

@Composable
private fun serviceTitle(kind: String): String = stringResource(
    when (kind) {
        // A record names its services `master_dns`; a client config says `masterdns`.
        "master_dns", "masterdns" -> R.string.ms_service_masterdns
        "xhttp" -> R.string.ms_service_xhttp
        else -> R.string.ms_service_reality
    },
)

// ------------------------------------------------------------------- form

@Composable
private fun FormPage(model: MyServerModel) {
    val form = model.form
    val c = ZeroTheme.colors
    Field(R.string.ms_field_name) {
        ZeroTextField(form.name, { form.name = it }, placeholder = stringResource(R.string.ms_default_name))
    }
    Field(R.string.ms_field_address) {
        ZeroTextField(form.address, { form.address = it; form.error = null }, placeholder = "203.0.113.7", keyboardType = KeyboardType.Uri)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f)) {
            Field(R.string.ms_field_port) {
                ZeroTextField(form.port, { form.port = it.filter(Char::isDigit).take(5) }, keyboardType = KeyboardType.Number)
            }
        }
        Column(Modifier.weight(1f)) {
            Field(R.string.ms_field_user) { ZeroTextField(form.user, { form.user = it }) }
        }
    }
    Field(R.string.ms_login_with) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ZeroChip(stringResource(R.string.ms_login_password), { form.useKey = false; form.error = null }, selected = !form.useKey)
            ZeroChip(stringResource(R.string.ms_login_key), { form.useKey = true; form.error = null }, selected = form.useKey)
        }
    }
    if (form.useKey) KeyFields(form) else {
        Field(R.string.ms_field_password) {
            ZeroTextField(
                form.password,
                { form.password = it; form.error = null },
                keyboardType = KeyboardType.Password,
                visualTransformation = PasswordVisualTransformation(),
            )
        }
        Small(stringResource(R.string.ms_password_note))
    }
    Spacer(Modifier.height(16.dp))
    Text(stringResource(R.string.ms_what_to_install), style = MaterialTheme.typography.titleSmall, color = c.text)
    ToggleRow(
        stringResource(R.string.ms_service_reality),
        form.reality,
        { form.reality = it; form.error = null },
        subtitle = stringResource(R.string.ms_reality_note),
    )
    ToggleRow(
        stringResource(R.string.ms_service_xhttp),
        form.xhttp,
        { form.xhttp = it; form.error = null },
        subtitle = stringResource(R.string.ms_xhttp_note),
    )
    ToggleRow(
        stringResource(R.string.ms_service_masterdns),
        form.masterdns,
        { form.masterdns = it; form.error = null },
        subtitle = stringResource(R.string.ms_masterdns_note),
    )
    if (form.masterdns) {
        Field(R.string.ms_field_domain) {
            ZeroTextField(form.domain, { form.domain = it; form.error = null }, placeholder = "t.example.com", keyboardType = KeyboardType.Uri)
        }
        Small(stringResource(R.string.ms_domain_note))
    }
    form.error?.let {
        Spacer(Modifier.height(12.dp))
        Text(it, color = c.err, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    }
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.ms_connect), model::submit, Modifier.fillMaxWidth())
}

/** The private-key login: paste the text or pick the file, and a passphrase when the key has one. */
@Composable
private fun KeyFields(form: MsForm) {
    val context = LocalContext.current
    val unreadable = stringResource(R.string.ms_key_unreadable)
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        // A private key is a few kilobytes; anything much bigger is not one.
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                while (out.size() < 64 * 1024) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    out.write(buffer, 0, read)
                }
                out.toString("UTF-8")
            }
        }.getOrNull()
        if (text.isNullOrBlank()) form.error = unreadable else { form.keyText = text; form.error = null }
    }
    Field(R.string.ms_field_key) {
        ZeroTextField(
            form.keyText,
            { form.keyText = it; form.error = null },
            placeholder = stringResource(R.string.ms_key_hint),
            singleLine = false,
            minLines = 4,
            maxLines = 8,
            keyboardType = KeyboardType.Ascii,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
    }
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_key_choose), { picker.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth())
    Field(R.string.ms_field_passphrase) {
        ZeroTextField(
            form.passphrase,
            { form.passphrase = it; form.error = null },
            keyboardType = KeyboardType.Password,
            visualTransformation = PasswordVisualTransformation(),
        )
    }
    Small(stringResource(R.string.ms_key_note))
}

@Composable
private fun Field(label: Int, content: @Composable () -> Unit) {
    Text(stringResource(label), style = MaterialTheme.typography.labelMedium, color = ZeroTheme.colors.muted, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
    content()
}

// --------------------------------------------------------------- identity

@Composable
private fun IdentityPage(model: MyServerModel, screen: MsScreen.Identity) {
    Body(stringResource(R.string.ms_identity_body))
    Spacer(Modifier.height(12.dp))
    ZeroCard {
        SelectionContainer {
            Text(ltr(screen.fingerprint), style = MaterialTheme.typography.bodyLarge, color = ZeroTheme.colors.accent)
        }
    }
    Spacer(Modifier.height(12.dp))
    Small(stringResource(R.string.ms_identity_help))
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.ms_identity_yes), model::trustIdentity, Modifier.fillMaxWidth())
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_identity_no), model::back, Modifier.fillMaxWidth())
}

// -------------------------------------------------------------------- dns

@Composable
private fun DnsPage(model: MyServerModel, screen: MsScreen.Dns) {
    val c = ZeroTheme.colors
    Body(stringResource(R.string.ms_dns_step1))
    Spacer(Modifier.height(6.dp))
    Body(stringResource(R.string.ms_dns_step2))
    Spacer(Modifier.height(12.dp))
    screen.records.forEachIndexed { index, record ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Text(stringResource(R.string.ms_dns_record, index + 1, record.kind), style = MaterialTheme.typography.labelLarge, color = c.text)
            Spacer(Modifier.height(6.dp))
            CopyLine(stringResource(R.string.ms_dns_name), record.name) { model.copy(record.name, false) }
            CopyLine(stringResource(if (record.kind == "NS") R.string.ms_dns_nameserver else R.string.ms_dns_value), record.value) { model.copy(record.value, false) }
        }
    }
    if (screen.needsIp) {
        Text(stringResource(R.string.ms_dns_needs_ip), color = c.warn, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
    }
    Body(stringResource(R.string.ms_dns_step3))
    Spacer(Modifier.height(4.dp))
    Small(stringResource(R.string.ms_dns_other))
    Spacer(Modifier.height(12.dp))
    val (text, color) = when (screen.status) {
        DnsStatus.NotChecked -> stringResource(R.string.ms_dns_not_checked) to c.muted
        DnsStatus.Checking -> stringResource(R.string.ms_dns_checking) to c.muted
        DnsStatus.Right -> stringResource(R.string.ms_dns_right) to c.accent
        DnsStatus.Wrong -> stringResource(R.string.ms_dns_wrong) to c.warn
        DnsStatus.Unknown -> stringResource(R.string.ms_dns_unknown) to c.warn
    }
    Text(text, color = color, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    Spacer(Modifier.height(16.dp))
    TonalButton(stringResource(R.string.ms_dns_check), model::checkDns, Modifier.fillMaxWidth(), enabled = screen.status != DnsStatus.Checking)
    Spacer(Modifier.height(8.dp))
    PrimaryButton(stringResource(R.string.ms_dns_install), { model.install() }, Modifier.fillMaxWidth())
}

@Composable
private fun CopyLine(label: String, value: String, onCopy: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Small(label)
            Text(ltr(value), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.text)
        }
        TonalButton(stringResource(R.string.ms_copy), onCopy)
    }
}

// --------------------------------------------------------------- progress

@Composable
private fun ProgressPage(model: MyServerModel, screen: MsScreen.Progress) {
    val c = ZeroTheme.colors
    Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite }) {
        screen.steps.forEach { step ->
            Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(if (step.done) "✓" else "…", color = if (step.done) c.accent else c.text, modifier = Modifier.widthIn(min = 24.dp))
                Text(stepName(step), color = if (step.done) c.muted else c.text, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    if (screen.failed != null) {
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.ms_failed), color = c.err, style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(4.dp))
        Text(screen.failed, color = c.err, style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(4.dp))
        Small(stringResource(R.string.ms_failed_note))
        Spacer(Modifier.height(16.dp))
        PrimaryButton(stringResource(R.string.ms_back), model::back, Modifier.fillMaxWidth())
    } else {
        if (screen.detail.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Small(screen.detail)
        }
        Spacer(Modifier.height(10.dp))
        Small(stringResource(R.string.ms_progress_wait))
    }
}

@Composable
private fun stepName(step: StepView): String {
    val base = stringResource(
        when (step.step) {
            "check" -> R.string.ms_step_check
            "packages" -> R.string.ms_step_packages
            "download" -> R.string.ms_step_download
            "install" -> R.string.ms_step_install
            "configure" -> R.string.ms_step_configure
            "start" -> R.string.ms_step_start
            "firewall" -> R.string.ms_step_firewall
            else -> R.string.ms_step_access
        },
    )
    return when (step.preset) {
        "reality" -> "$base (REALITY)"
        "xhttp" -> "$base (XHTTP)"
        "master_dns" -> "$base (MasterDNS)"
        else -> base
    }
}

// ----------------------------------------------------------------- result

@Composable
private fun ResultPage(model: MyServerModel, screen: MsScreen.Result) {
    val entry = model.entry(screen.id) ?: return
    Text(stringResource(R.string.ms_ready, entry.name), color = ZeroTheme.colors.accent, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(12.dp))
    ConfigBlock(model, entry)
    screen.notes.filter { it.isNotEmpty() }.forEach {
        Spacer(Modifier.height(12.dp))
        Text(it, color = ZeroTheme.colors.warn, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.ms_open_server), { model.openServer(entry.id) }, Modifier.fillMaxWidth())
}

/** The config being shown: its link and code, and what to do with it. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ConfigBlock(model: MyServerModel, entry: MyServerStore.Entry) {
    val configs = remember(entry) { model.configs(entry.id) }
    if (configs.isEmpty()) return
    val index = model.shown.coerceIn(0, configs.lastIndex)
    val config = configs[index]
    if (configs.size > 1) {
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(bottom = 8.dp),
        ) {
            configs.forEachIndexed { i, c ->
                val label = serviceTitle(c.service)
                ZeroChip(label, { model.shown = i; model.bigQr = false }, selected = i == index)
            }
        }
    }
    Text(stringResource(R.string.ms_config_for, config.user), style = MaterialTheme.typography.titleSmall, color = ZeroTheme.colors.text)
    Spacer(Modifier.height(8.dp))
    val link = config.link
    if (link != null) {
        if (model.bigQr) {
            QrCode(link, stringResource(R.string.ms_qr_description), Modifier.fillMaxWidth().widthIn(max = 360.dp))
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.ms_hide_code), { model.bigQr = false }, Modifier.fillMaxWidth())
        } else {
            ZeroCard(Modifier.fillMaxWidth()) {
                SelectionContainer {
                    Text(ltr(link), style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.text, maxLines = 6)
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(stringResource(R.string.ms_copy_link), { model.copy(link, true) }, Modifier.weight(1f))
                TonalButton(stringResource(R.string.ms_show_code), { model.bigQr = true }, Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.ms_use_here), { model.useInApp(entry.id) }, Modifier.fillMaxWidth())
        }
    }
    if (config.files.isNotEmpty()) {
        Body(stringResource(R.string.ms_files_note), muted = true)
        Spacer(Modifier.height(8.dp))
        config.files.forEach { (name, text) ->
            Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(ltr(name), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.text)
                TonalButton(stringResource(R.string.ms_copy), { model.copy(text, true) })
                Spacer(Modifier.padding(horizontal = 4.dp))
                TonalButton(stringResource(R.string.ms_share), {
                    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text).putExtra(Intent.EXTRA_SUBJECT, name)
                    model.startIntent(Intent.createChooser(send, name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                })
            }
        }
        Spacer(Modifier.height(4.dp))
        Small(stringResource(R.string.ms_files_secret))
    }
}

// ----------------------------------------------------------------- server

@Composable
private fun ServerPage(model: MyServerModel, screen: MsScreen.Server) {
    val entry = model.entry(screen.id)
    if (entry == null) {
        Body(stringResource(R.string.ms_gone))
        return
    }
    LaunchedEffect(screen.id) { model.watchUsage(screen.id) }
    androidx.compose.runtime.DisposableEffect(screen.id) { onDispose { model.stopWatching() } }
    val c = ZeroTheme.colors
    Text(ltr(entry.host), color = c.muted, style = MaterialTheme.typography.bodyMedium)
    model.notice?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, color = c.accent, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    }
    Spacer(Modifier.height(12.dp))
    UsageBlock(model, entry)
    Spacer(Modifier.height(16.dp))
    ConfigBlock(model, entry)
    if (entry.kinds.contains("master_dns")) {
        Spacer(Modifier.height(8.dp))
        TonalButton(stringResource(R.string.ms_test), { model.probe(entry.id) }, Modifier.fillMaxWidth())
    }
    Spacer(Modifier.height(16.dp))
    TonalButton(stringResource(R.string.ms_remove), { model.askRemove(entry.id) }, Modifier.fillMaxWidth(), tint = c.err)
}

@Composable
private fun UsageBlock(model: MyServerModel, entry: MyServerStore.Entry) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    Text(stringResource(R.string.ms_live), style = MaterialTheme.typography.titleSmall, color = c.text)
    Spacer(Modifier.height(6.dp))
    val usage = model.usage[entry.id]
    if (usage == null) {
        Small(model.usageError[entry.id] ?: stringResource(R.string.ms_reading))
        return
    }
    entry.kinds.forEach { kind ->
        val row = usage.inbounds.firstOrNull { it.tag == entry.tagOf(kind) }
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Text(serviceTitle(kind), style = MaterialTheme.typography.labelLarge, color = c.text)
            Spacer(Modifier.height(6.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Stat(stringResource(R.string.ms_stat_now), (row?.now ?: 0).toString(), strong = true)
                Stat(stringResource(R.string.ms_stat_recent, (usage.windowSecs / 60).toInt()), (row?.recent ?: 0).toString())
                Stat(stringResource(R.string.ms_stat_sessions), (row?.sessions ?: 0).toString())
            }
            if (kind == "master_dns") {
                Spacer(Modifier.height(6.dp))
                Small(stringResource(R.string.ms_masterdns_lag))
            } else if (row != null) {
                Spacer(Modifier.height(6.dp))
                Small(stringResource(R.string.ms_traffic, ltr(Formatter.formatShortFileSize(context, row.up)), ltr(Formatter.formatShortFileSize(context, row.down))))
            }
        }
    }
    model.usageError[entry.id]?.let { Text(it, color = c.warn, style = MaterialTheme.typography.bodySmall) }
    Small(stringResource(R.string.ms_privacy))
}

@Composable
private fun Stat(label: String, value: String, strong: Boolean = false) {
    Column {
        Text(
            value,
            style = MaterialTheme.typography.titleLarge,
            color = if (strong) ZeroTheme.colors.accent else ZeroTheme.colors.text,
        )
        Small(label)
    }
}

// ---------------------------------------------------------------- confirm

@Composable
private fun ConfirmPage(model: MyServerModel, screen: MsScreen.ConfirmRemove) {
    val c = ZeroTheme.colors
    val name = model.entry(screen.id)?.name.orEmpty()
    var typed by remember { mutableStateOf("") }
    val word = stringResource(R.string.ms_remove_word)
    Text(stringResource(R.string.ms_remove_what, name), color = c.warn, style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(8.dp))
    Body(stringResource(R.string.ms_remove_detail), muted = true)
    Spacer(Modifier.height(12.dp))
    Body(stringResource(R.string.ms_remove_type, word))
    Spacer(Modifier.height(8.dp))
    ZeroTextField(typed, { typed = it }, placeholder = word)
    Spacer(Modifier.height(16.dp))
    PrimaryButton(
        stringResource(R.string.ms_remove_confirm),
        { model.remove(screen.id) },
        Modifier.fillMaxWidth(),
        enabled = typed.trim().equals(word, ignoreCase = true),
        container = c.err,
    )
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_cancel), model::back, Modifier.fillMaxWidth())
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_forget), { model.forget(screen.id) }, Modifier.fillMaxWidth())
    Spacer(Modifier.height(4.dp))
    Small(stringResource(R.string.ms_forget_note))
}
