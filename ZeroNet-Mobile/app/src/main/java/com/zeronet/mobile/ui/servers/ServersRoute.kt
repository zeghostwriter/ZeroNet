package com.zeronet.mobile.ui.servers

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zeronet.mobile.R
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.ui.LocalController

@Composable
fun ServersRoute() {
    val controller = LocalController.current
    val resources = androidx.compose.ui.platform.LocalResources.current
    val servers by controller.servers.servers.collectAsStateWithLifecycle()
    val subscriptions by controller.servers.subscriptions.collectAsStateWithLifecycle()
    val refreshing by controller.engine.refreshing.collectAsStateWithLifecycle()
    val testProgress by controller.engine.testProgress.collectAsStateWithLifecycle()
    val conn by controller.engine.state.collectAsStateWithLifecycle()

    var segment by rememberSaveable { mutableStateOf(ServersSegment.Recommended) }
    var query by rememberSaveable { mutableStateOf("") }
    var expanded by rememberSaveable { mutableStateOf(emptyList<String>()) }
    var detailKey by rememberSaveable { mutableStateOf<String?>(null) }
    var importOpen by rememberSaveable { mutableStateOf(false) }
    var importText by remember { mutableStateOf<String?>(null) }

    // Text shared into the app (or a tapped vless:// link) opens the import sheet prefilled.
    val pending = controller.pendingImport
    LaunchedEffect(pending) {
        if (pending != null) {
            segment = ServersSegment.Mine
            importText = pending
            importOpen = true
            controller.pendingImport = null
        }
    }

    val activeKey = (conn as? ConnState.Connected)?.server?.key
    ServersScreen(
        state = ServersState(
            servers = servers,
            subscriptions = subscriptions,
            segment = segment,
            query = query,
            expanded = expanded.toSet(),
            refreshing = refreshing,
            testProgress = testProgress,
            activeKey = activeKey,
        ),
        actions = remember(controller) {
            ServersActions(
                onSegment = { segment = it },
                onQuery = { query = it },
                onToggleCountry = { code -> expanded = if (code in expanded) expanded - code else expanded + code },
                onRefresh = { controller.engine.refresh() },
                onTest = { keys -> controller.engine.test(keys) },
                onConnect = { controller.selectTarget(it) },
                onFavorite = { s, fav -> controller.servers.setFavorite(s.key, fav) },
                onDetails = { detailKey = it.key },
                onAdd = { importText = null; importOpen = true },
                onRemoveSubscription = { controller.engine.removeSubscription(it.id) },
            )
        },
    )

    val detail = remember(detailKey, servers) { detailKey?.let { k -> servers.firstOrNull { it.key == k } } }
    ServerDetailSheet(
        server = detail,
        subscriptions = subscriptions,
        testing = testProgress != null,
        now = System.currentTimeMillis(),
        onConnect = {
            detailKey = null
            controller.selectTarget(com.zeronet.mobile.model.ConnectTarget.Specific(it.key))
        },
        onTest = { controller.engine.test(listOf(it.key)) },
        onCopyLink = { controller.copy(it.link, sensitive = true) },
        onFavorite = { s, fav -> controller.servers.setFavorite(s.key, fav) },
        onDelete = {
            controller.servers.delete(listOf(it.key))
            detailKey = null
            controller.messages.show(resources.getString(R.string.msg_deleted))
        },
        onDismiss = { detailKey = null },
    )

    ImportSheet(
        visible = importOpen,
        initialText = importText,
        onImport = { text -> controller.engine.import(text) },
        onAddSubscription = { name, url ->
            controller.engine.addSubscription(name, url)
            controller.messages.show(resources.getString(R.string.msg_subscription_added))
            importOpen = false
        },
        readClipboard = controller::readClipboard,
        onDismiss = { importOpen = false },
    )
}
