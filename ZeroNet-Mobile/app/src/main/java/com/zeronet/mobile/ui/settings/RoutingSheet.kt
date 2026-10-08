package com.zeronet.mobile.ui.settings

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.RoutingProfile
import com.zeronet.mobile.model.RoutingRule
import com.zeronet.mobile.model.RuleAction
import com.zeronet.mobile.model.RuleNetwork
import com.zeronet.mobile.model.RuleProblem
import com.zeronet.mobile.model.Settings
import com.zeronet.mobile.ui.components.Hairline
import com.zeronet.mobile.ui.components.IconAction
import com.zeronet.mobile.ui.components.LabeledBlock
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.RowShape
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Routing profiles: the user's own rules for what goes through the tunnel,
 * straight out, or nowhere, by domain, address, port or app. One profile is
 * in use at a time (or none); its rules run before the built-in ones, and the
 * engine applies a change while connected.
 *
 * The sheet has three pages, one at a time: the profiles, the rules of one
 * profile, and one rule being written (with a page for choosing its apps).
 * A rule is only kept when it can be used ([RoutingRule.problem]).
 */
@Composable
fun RoutingSheet(visible: Boolean, s: Settings, actions: SettingsActions, onDismiss: () -> Unit) {
    val title = stringResource(R.string.routing_title)
    // Which profile is open, which of its rules is being written (-1 for a
    // new one) and whether that rule's apps are being picked.
    var open by rememberSaveable { mutableStateOf<String?>(null) }
    var editing by rememberSaveable { mutableStateOf<Int?>(null) }
    var draft by remember { mutableStateOf(RoutingRule()) }
    var pickingApps by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(visible) {
        if (!visible) {
            open = null; editing = null; pickingApps = false
        }
    }
    fun update(change: (List<RoutingProfile>) -> List<RoutingProfile>, active: (String) -> String = { it }) =
        actions.onChange { it.copy(routingProfiles = change(it.routingProfiles), routingProfile = active(it.routingProfile)) }

    ZeroSheet(visible = visible, onDismiss = onDismiss, title = title) {
        val profile = s.routingProfiles.firstOrNull { it.name == open }
        when {
            profile == null -> ProfilesPage(title, s, onOpen = { open = it }, onCreate = { name ->
                update({ it + RoutingProfile(name) })
                open = name
            }, onUse = { name -> update({ it }) { current -> if (current == name) "" else name } })
            editing != null && pickingApps -> AppsPage(draft.apps, onChange = { draft = draft.copy(apps = it) }, onDone = { pickingApps = false })
            editing != null -> RulePage(
                draft,
                isNew = editing == -1,
                onChange = { draft = it },
                onPickApps = { pickingApps = true },
                onSave = {
                    val at = editing ?: -1
                    update({ list ->
                        list.map { p ->
                            if (p.name != profile.name) p
                            else p.copy(rules = if (at in p.rules.indices) p.rules.toMutableList().also { it[at] = draft } else p.rules + draft)
                        }
                    })
                    editing = null
                },
                onDelete = {
                    val at = editing ?: -1
                    update({ list -> list.map { p -> if (p.name != profile.name) p else p.copy(rules = p.rules.filterIndexed { i, _ -> i != at }) } })
                    editing = null
                },
                onBack = { editing = null },
            )
            else -> ProfilePage(
                profile,
                inUse = s.routingProfile == profile.name,
                taken = s.routingProfiles.map { it.name }.toSet() - profile.name,
                onBack = { open = null },
                onUse = { use -> update({ it }) { if (use) profile.name else if (it == profile.name) "" else it } },
                onRename = { name ->
                    update({ list -> list.map { if (it.name == profile.name) it.copy(name = name) else it } }) { if (it == profile.name) name else it }
                    open = name
                },
                onDeleteProfile = {
                    update({ list -> list.filter { it.name != profile.name } }) { if (it == profile.name) "" else it }
                    open = null
                },
                onRules = { rules -> update({ list -> list.map { if (it.name == profile.name) it.copy(rules = rules) else it } }) },
                onEdit = { index ->
                    draft = profile.rules.getOrNull(index) ?: RoutingRule()
                    editing = if (index in profile.rules.indices) index else -1
                },
            )
        }
    }
}

@Composable
private fun ColumnScope.ProfilesPage(
    title: String,
    s: Settings,
    onOpen: (String) -> Unit,
    onCreate: (String) -> Unit,
    onUse: (String) -> Unit,
) {
    val c = ZeroTheme.colors
    SheetHeader(title, stringResource(R.string.routing_body))
    SheetBody {
        Choice(stringResource(R.string.routing_none), s.routingProfile.isEmpty(), onClick = { if (s.routingProfile.isNotEmpty()) onUse(s.routingProfile) })
        s.routingProfiles.forEach { profile ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Choice(profile.name, s.routingProfile == profile.name, Modifier.weight(1f), onClick = { onUse(profile.name) })
                Text(
                    androidx.compose.ui.res.pluralStringResource(R.plurals.routing_rule_count, profile.rules.size, profile.rules.size),
                    style = MaterialTheme.typography.bodySmall, color = c.muted,
                )
                IconAction(ZeroIcons.ChevronEnd, stringResource(R.string.routing_edit_profile), { onOpen(profile.name) })
            }
        }
        Spacer(Modifier.height(12.dp))
        var name by rememberSaveable { mutableStateOf("") }
        val trimmed = name.trim()
        val taken = s.routingProfiles.any { it.name == trimmed }
        ZeroTextField(name, { name = it }, placeholder = stringResource(R.string.routing_new_name))
        if (taken) Hint(stringResource(R.string.routing_name_taken), c.err)
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.routing_new),
            onClick = { onCreate(trimmed); name = "" },
            enabled = trimmed.isNotEmpty() && !taken,
            icon = ZeroIcons.Plus,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun ColumnScope.ProfilePage(
    profile: RoutingProfile,
    inUse: Boolean,
    taken: Set<String>,
    onBack: () -> Unit,
    onUse: (Boolean) -> Unit,
    onRename: (String) -> Unit,
    onDeleteProfile: () -> Unit,
    onRules: (List<RoutingRule>) -> Unit,
    onEdit: (Int) -> Unit,
) {
    val c = ZeroTheme.colors
    BackRow(profile.name, onBack)
    SheetBody {
        ToggleRow(stringResource(R.string.routing_use), inUse, onUse, subtitle = stringResource(R.string.routing_use_hint))
        Hairline()
        Spacer(Modifier.height(8.dp))
        if (profile.rules.isEmpty()) Hint(stringResource(R.string.routing_no_rules), c.muted)
        profile.rules.forEachIndexed { index, rule ->
            RuleRow(
                rule,
                onClick = { onEdit(index) },
                onToggle = { on -> onRules(profile.rules.toMutableList().also { it[index] = rule.copy(enabled = on) }) },
                onUp = if (index > 0) ({ onRules(profile.rules.toMutableList().also { it.add(index - 1, it.removeAt(index)) }) }) else null,
            )
        }
        Spacer(Modifier.height(8.dp))
        PrimaryButton(stringResource(R.string.routing_add_rule), onClick = { onEdit(-1) }, icon = ZeroIcons.Plus, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(20.dp))
        var name by rememberSaveable(profile.name) { mutableStateOf(profile.name) }
        val trimmed = name.trim()
        LabeledBlock(stringResource(R.string.routing_rename)) {
            ZeroTextField(name, { name = it })
            if (trimmed in taken) Hint(stringResource(R.string.routing_name_taken), c.err)
            Spacer(Modifier.height(8.dp))
            TonalButton(
                stringResource(R.string.routing_rename),
                onClick = { onRename(trimmed) },
                enabled = trimmed.isNotEmpty() && trimmed != profile.name && trimmed !in taken,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(8.dp))
        TonalButton(stringResource(R.string.routing_delete_profile), onClick = onDeleteProfile, icon = ZeroIcons.Trash, tint = c.err, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun RuleRow(rule: RoutingRule, onClick: () -> Unit, onToggle: (Boolean) -> Unit, onUp: (() -> Unit)?) {
    val c = ZeroTheme.colors
    val (label, color) = actionLabel(rule.action)
    val faded = if (rule.enabled) 1f else 0.45f
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).clip(RowShape).clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelLarge, color = color.copy(alpha = faded))
            Text(
                summary(rule), style = MaterialTheme.typography.bodySmall, color = c.text.copy(alpha = faded),
                maxLines = 2, overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace,
            )
        }
        if (onUp != null) IconAction(ZeroIcons.ArrowUp, stringResource(R.string.routing_move_up), onUp)
        androidx.compose.material3.Switch(checked = rule.enabled, onCheckedChange = onToggle)
    }
}

@Composable
private fun ColumnScope.RulePage(
    rule: RoutingRule,
    isNew: Boolean,
    onChange: (RoutingRule) -> Unit,
    onPickApps: () -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
    onBack: () -> Unit,
) {
    val c = ZeroTheme.colors
    BackRow(stringResource(if (isNew) R.string.routing_new_rule else R.string.routing_edit_rule), onBack)
    SheetBody {
        LabeledBlock(stringResource(R.string.routing_action)) {
            Segmented(RuleAction.entries, rule.action, { onChange(rule.copy(action = it)) }, label = { actionLabel(it).first })
        }
        // The lists are edited as text and split when kept, so typing a
        // comma does not jump the cursor.
        var domains by rememberSaveable { mutableStateOf(rule.domains.joinToString(", ")) }
        var addresses by rememberSaveable { mutableStateOf(rule.addresses.joinToString(", ")) }
        LabeledBlock(stringResource(R.string.routing_domains), subtitle = stringResource(R.string.routing_domains_hint)) {
            ZeroTextField(domains, { domains = it; onChange(rule.copy(domains = RoutingRule.entries(it))) }, singleLine = false, minLines = 2, keyboardType = KeyboardType.Uri)
        }
        LabeledBlock(stringResource(R.string.routing_addresses), subtitle = stringResource(R.string.routing_addresses_hint)) {
            ZeroTextField(addresses, { addresses = it; onChange(rule.copy(addresses = RoutingRule.entries(it))) }, singleLine = false, minLines = 1, keyboardType = KeyboardType.Uri)
        }
        NavRow(
            stringResource(R.string.routing_apps),
            onPickApps,
            icon = ZeroIcons.Apps,
            value = if (rule.apps.isEmpty()) stringResource(R.string.settings_apps_none) else androidx.compose.ui.res.pluralStringResource(R.plurals.apps_selected, rule.apps.size, rule.apps.size),
            subtitle = stringResource(R.string.routing_apps_hint),
        )
        LabeledBlock(stringResource(R.string.routing_ports), subtitle = stringResource(R.string.routing_ports_hint)) {
            ZeroTextField(rule.port, { onChange(rule.copy(port = it.filter { ch -> ch.isDigit() || ch == ',' || ch == '-' })) }, keyboardType = KeyboardType.Number)
        }
        LabeledBlock(stringResource(R.string.routing_network)) {
            Segmented(RuleNetwork.entries, rule.network, { onChange(rule.copy(network = it)) }, label = {
                stringResource(when (it) { RuleNetwork.Any -> R.string.routing_network_any; RuleNetwork.Tcp -> R.string.routing_network_tcp; RuleNetwork.Udp -> R.string.routing_network_udp })
            })
        }
        val problem = rule.problem()
        if (problem != null) {
            Hint(stringResource(when (problem) { RuleProblem.Empty -> R.string.routing_problem_empty; RuleProblem.Port -> R.string.routing_problem_port }), c.warn)
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!isNew) TonalButton(stringResource(R.string.routing_delete_rule), onClick = onDelete, icon = ZeroIcons.Trash, tint = c.err, modifier = Modifier.weight(1f))
            PrimaryButton(stringResource(R.string.routing_save_rule), onClick = onSave, enabled = problem == null, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun ColumnScope.AppsPage(chosen: List<String>, onChange: (List<String>) -> Unit, onDone: () -> Unit) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val apps by produceState<List<AppEntry>?>(null) {
        value = withContext(Dispatchers.IO) { runCatching { loadApps(context.packageManager, context.packageName) }.getOrDefault(emptyList()) }
    }
    BackRow(stringResource(R.string.routing_apps), onDone)
    SheetBody {
        Hint(stringResource(R.string.routing_apps_hint), c.muted)
        val list = apps ?: return@SheetBody
        // Chosen first; a package no longer installed stays listed so it can be removed.
        val known = list.map { it.pkg }.toSet()
        val missing = chosen.filter { it !in known }.map { AppEntry(it, it) }
        (missing + list.sortedBy { if (it.pkg in chosen) 0 else 1 }).forEach { app ->
            val checked = app.pkg in chosen
            Row(
                Modifier.fillMaxWidth().heightIn(min = 56.dp).clip(RowShape)
                    .toggleable(checked, role = Role.Checkbox) { on -> onChange(if (on) chosen + app.pkg else chosen - app.pkg) }
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AppIcon(app.pkg)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(app.label, style = MaterialTheme.typography.bodyLarge, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(app.pkg, style = MaterialTheme.typography.bodySmall, color = c.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                CheckMark(checked)
            }
        }
    }
}

@Composable
private fun BackRow(title: String, onBack: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        IconAction(ZeroIcons.Back, stringResource(R.string.action_back), onBack)
        Text(title, style = MaterialTheme.typography.titleLarge, color = ZeroTheme.colors.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun Choice(title: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val c = ZeroTheme.colors
    Row(
        modifier.fillMaxWidth().heightIn(min = 52.dp).clip(RowShape).clickable(role = Role.RadioButton, onClick = onClick).padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        androidx.compose.material3.RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.width(8.dp))
        Text(title, style = MaterialTheme.typography.bodyLarge, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun Hint(text: String, color: Color) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.padding(vertical = 4.dp))
}

@Composable
private fun actionLabel(action: RuleAction): Pair<String, Color> {
    val c = ZeroTheme.colors
    return when (action) {
        RuleAction.Proxy -> stringResource(R.string.routing_action_proxy) to c.info
        RuleAction.Direct -> stringResource(R.string.routing_action_direct) to c.ok
        RuleAction.Block -> stringResource(R.string.routing_action_block) to c.err
    }
}

/** What a rule matches, in one or two short lines. */
private fun summary(rule: RoutingRule): String = buildList {
    if (rule.domains.isNotEmpty()) add(rule.domains.joinToString(", "))
    if (rule.addresses.isNotEmpty()) add(rule.addresses.joinToString(", "))
    if (rule.apps.isNotEmpty()) add(rule.apps.joinToString(", "))
    if (rule.port.isNotBlank()) add(":" + rule.port)
    if (rule.network != RuleNetwork.Any) add(rule.network.wire)
}.joinToString(" · ")
