package com.zeronet.mobile

import android.app.Application
import android.os.Process
import com.zeronet.mobile.service.Engine

/**
 * Two processes run this class: the UI (main) process and the :vpn process.
 * Only :vpn touches native code; the UI process does nothing here, so its
 * cold start stays as short as possible.
 */
class ZeroApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (isVpnProcess()) Engine.init(this)
    }

    private fun isVpnProcess(): Boolean {
        val name = if (android.os.Build.VERSION.SDK_INT >= 28) {
            getProcessName()
        } else {
            runCatching { java.io.File("/proc/${Process.myPid()}/cmdline").readText().trim('\u0000', ' ', '\n') }.getOrDefault("")
        }
        return name.endsWith(":vpn")
    }
}
