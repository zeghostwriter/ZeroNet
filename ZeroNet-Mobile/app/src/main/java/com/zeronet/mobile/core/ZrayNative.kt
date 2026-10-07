package com.zeronet.mobile.core

/**
 * Receives batches of newline-separated JSON events from a native job.
 * Called on a Rust thread; must not block.
 */
fun interface NativeListener {
    fun onEvents(batch: String)
}

/**
 * The Kotlin half of docs/native-contract.md. Loaded only in the :vpn process.
 */
object ZrayNative {
    init {
        System.loadLibrary("zray_mobile")
    }

    @JvmStatic external fun init(dataDir: String, logLevel: String): String?

    /** Change the core's log level ("warn", "info", "debug"…) live. */
    @JvmStatic external fun setLogLevel(level: String): String?

    @JvmStatic external fun setTun(fd: Int, mtu: Int): String?
    @JvmStatic external fun start(configJson: String): String?
    @JvmStatic external fun reload(configJson: String): String?
    @JvmStatic external fun stop(): String?
    @JvmStatic external fun isRunning(): Boolean
    @JvmStatic external fun stats(): String?
    @JvmStatic external fun networkChanged(): String?

    @JvmStatic external fun buildConfig(requestJson: String): String
    /** The user's switch for the decoy server name: off stops the core from
     *  turning to it by itself. Takes effect on the next connection. */
    @JvmStatic external fun setDecoy(enabled: Boolean)
    /** `{"supported", "local", "network"}`: whether the decoy works on this
     *  phone and on this network. Blocks for seconds; call off the main thread. */
    @JvmStatic external fun decoyCheck(): String
    @JvmStatic external fun parseLinks(text: String): String
    @JvmStatic external fun subscriptionFetchUrl(address: String): String
    /** `{"links": [...], "seed": n, "max": n}` → `{"links": [...]}`: CDN-fronted
     *  TLS links re-aimed at Cloudflare edge IPs (SNI/Host kept). */
    @JvmStatic external fun frontLinks(requestJson: String): String

    /** Whether [signature] (an `ed25519:<hex>` line) signs [body] for [publicKeyHex]. */
    @JvmStatic external fun verifySignature(publicKeyHex: String, body: String, signature: String): Boolean
    /** The crowd-data signing key compiled into the library (hex), or "" when none was. */
    @JvmStatic external fun builtInPublicKey(): String

    @JvmStatic external fun discover(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun testLinks(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun scan(requestJson: String, listener: NativeListener): Long
    /** `{"proxy": "127.0.0.1:port"?, "direct": bool}` → events `{"t":"step","line"}` and one
     *  `{"t":"done","ok",…}`: gets a free WARP account and finds servers that work through it. */
    @JvmStatic external fun warpRegister(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun cancel(handle: Long)

    /** Called from Rust for every outbound socket Zray opens. */
    @JvmStatic
    fun protect(fd: Int): Boolean = SocketProtection.protect(fd)
}

/**
 * Routes socket protection to whichever VpnService is live. Zray installs one
 * process-wide protector, while VpnService instances come and go, so the
 * indirection lives here.
 */
object SocketProtection {
    fun interface Protector {
        fun protect(fd: Int): Boolean
    }

    @Volatile private var current: Protector? = null

    fun install(protector: Protector?) {
        current = protector
    }

    /** With no tunnel up there is nothing to escape from, so everything is "protected". */
    fun protect(fd: Int): Boolean = current?.protect(fd) ?: true
}
