package com.zeronet.mobile.ui.scanner

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zeronet.mobile.ui.LocalController

@Composable
fun ScannerRoute() {
    val controller = LocalController.current
    val scan by controller.engine.scan.collectAsStateWithLifecycle()
    ScannerScreen(
        state = scan,
        actions = remember(controller) {
            ScannerActions(
                onStart = { controller.engine.startScan() },
                onStop = { controller.engine.stopScan() },
                onCopy = { controller.copy(it.ip) },
                onCopyAll = { list -> controller.copy(list.joinToString("\n") { it.ip }) },
            )
        },
    )
}
