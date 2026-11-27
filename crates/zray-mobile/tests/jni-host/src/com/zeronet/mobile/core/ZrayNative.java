package com.zeronet.mobile.core;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Host-side stand-in for the app's {@code object ZrayNative}: the same static
 * natives (so the same JNI symbol names and signatures) plus the static
 * {@code protect(int)} callback Rust calls for every outbound socket.
 */
public final class ZrayNative {
    static { System.loadLibrary("zray_mobile"); }

    private ZrayNative() {}

    public static native String init(String dataDir, String logLevel);

    public static native String setTun(int fd, int mtu);
    public static native String start(String configJson);
    public static native String reload(String configJson);
    public static native String stop();
    public static native boolean isRunning();
    public static native String stats();
    public static native String networkChanged();

    public static native String buildConfig(String requestJson);
    public static native String parseLinks(String text);

    public static native long discover(String requestJson, NativeListener listener);
    public static native long testLinks(String requestJson, NativeListener listener);
    public static native long scan(String requestJson, NativeListener listener);
    public static native void cancel(long handle);

    /** Calls Rust made to protect a socket, and the thread names they came from. */
    public static final AtomicInteger PROTECT_CALLS = new AtomicInteger();
    public static volatile String lastProtectThread = "";

    /** Called BY Rust. No VpnService on the host, so every socket is fine as is. */
    public static boolean protect(int fd) {
        PROTECT_CALLS.incrementAndGet();
        lastProtectThread = Thread.currentThread().getName();
        return fd >= 0;
    }
}
