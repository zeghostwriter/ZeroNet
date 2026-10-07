package com.zeronet.mobile

import android.app.Application
import android.os.Process
import com.zeronet.mobile.core.LocalProxyAuth
import com.zeronet.mobile.service.Engine

/**
 * Two processes run this class: the UI (main) process and the :vpn process.
 * Only :vpn touches native code. The UI process only reads the local proxy's
 * password here (one small file), so its cold start stays as short as
 * possible; both processes make requests through that proxy and need it.
 */
class ZeroApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Before the engine builds a config that carries the password.
        LocalProxyAuth.init(this)
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
