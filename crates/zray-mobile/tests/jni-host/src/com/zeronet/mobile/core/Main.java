package com.zeronet.mobile.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Host smoke test for the JNI surface. Proves the exported symbol names and
 * signatures match {@code ZeroNet-Mobile/docs/native-contract.md} and that
 * callbacks (listener batches, socket protection) arrive from Rust threads.
 * Exits non-zero on the first failed check.
 */
public final class Main {
    private static int checks = 0;

    private static void check(boolean condition, String what) {
        checks++;
        if (!condition) {
            System.out.println("FAIL: " + what);
            System.exit(1);
        }
        System.out.println("ok   " + what);
    }

    /** Collects batches and signals when a {"t":"done"} event arrives. */
    static final class Collector implements NativeListener {
        final List<String> events = Collections.synchronizedList(new ArrayList<>());
        final CountDownLatch done = new CountDownLatch(1);
        final CountDownLatch any = new CountDownLatch(1);
        volatile int batches = 0;
        volatile String thread = "";

        @Override
        public void onEvents(String batch) {
            batches++;
            thread = Thread.currentThread().getName();
            for (String line : batch.split("\n")) {
                events.add(line);
                if (line.contains("\"t\":\"done\"")) done.countDown();
            }
            any.countDown();
        }

        long count(String type) {
            synchronized (events) {
                return events.stream().filter(e -> e.contains("\"t\":\"" + type + "\"")).count();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path dataDir = Files.createTempDirectory("zray-jni-host");

        // ---- init
        String initError = ZrayNative.init(dataDir.toString(), "debug");
        check(initError == null, "init(dataDir, debug) -> null  [" + initError + "]");
        check(ZrayNative.init(dataDir.toString(), "warn") == null, "init again only changes the level");
        check(ZrayNative.init(dataDir.toString(), "loud") != null, "init rejects an unknown level");
        check(Files.exists(dataDir.resolve("zray.log")), "log file created in dataDir");

        // ---- parseLinks
        String reality = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443"
                + "?security=reality&sni=www.googletagmanager.com&fp=chrome"
                + "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef"
                + "&type=tcp&encryption=none#%F0%9F%87%A9%F0%9F%87%AA%20Frankfurt";
        String ss = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@127.0.0.1:1#unreachable";
        String parsed = ZrayNative.parseLinks("Channel: https://t.me/x\n" + reality + "\n" + ss + "\nvless://broken\n");
        System.out.println("     parseLinks -> " + parsed);
        check(parsed.contains("\"items\":[") && parsed.contains("\"country\":\"DE\"")
                && parsed.contains("\"class\":\"reality\"") && parsed.contains("\"rejected\":1"),
                "parseLinks returns items, country, class and the rejection");

        // ---- buildConfig
        String built = ZrayNative.buildConfig("{\"links\":[\"" + reality + "\",\"" + ss + "\"],\"mode\":\"vpn\"}");
        check(built.startsWith("{\"config\":") && built.contains("\"tun-in\"") && built.contains("\"dns-out\"")
                && built.contains("\"leastPing\""), "buildConfig(vpn, 2 links) -> config with tun, dns-out, balancer");
        String bad = ZrayNative.buildConfig("{\"links\":[]}");
        check(bad.startsWith("{\"error\":"), "buildConfig without links -> {\"error\":...}  " + bad);
        check(ZrayNative.buildConfig("not json").startsWith("{\"error\":"), "buildConfig(garbage) -> error");

        // ---- runtime lifecycle, in proxy mode on private ports
        check(!ZrayNative.isRunning(), "isRunning() false before start");
        check(ZrayNative.stats() == null, "stats() null before start");
        check(ZrayNative.stop() != null, "stop() before start -> error string");
        check(ZrayNative.setTun(-1, 1500) != null, "setTun(-1) -> error string");
        String proxyConfig = ZrayNative.buildConfig("{\"links\":[\"" + ss + "\"],\"mode\":\"proxy\","
                + "\"socks_port\":31808,\"http_port\":31809}");
        String config = proxyConfig.substring("{\"config\":".length(), proxyConfig.length() - 1);
        String startError = ZrayNative.start(config);
        check(startError == null, "start(config) -> null  [" + startError + "]");
        check(ZrayNative.isRunning(), "isRunning() true after start");
        String stats = ZrayNative.stats();
        System.out.println("     stats -> " + stats);
        check(stats != null && stats.contains("\"up\":") && stats.contains("\"sessions\":") && stats.contains("\"tags\":"),
                "stats() has up/down/sessions/tags");
        check(ZrayNative.reload(config) == null, "reload(same config) -> null");
        check(ZrayNative.reload("{\"outbounds\":[{\"protocol\":\"freedom\"}]}") != null,
                "reload with a different inbound topology -> error string");
        check(ZrayNative.networkChanged() == null, "networkChanged() -> null");
        check(ZrayNative.start(config) != null, "second start -> error string");
        check(ZrayNative.stop() == null, "stop() -> null");
        check(!ZrayNative.isRunning(), "isRunning() false after stop");

        // ---- testLinks against an unreachable link (and a malformed one)
        int protectBefore = ZrayNative.PROTECT_CALLS.get();
        Collector test = new Collector();
        long handle = ZrayNative.testLinks("{\"links\":[\"" + ss + "\",\"vless://broken\"],\"timeout_ms\":1500}", test);
        check(handle > 0, "testLinks -> handle " + handle);
        check(test.done.await(20, TimeUnit.SECONDS), "testLinks delivers done");
        System.out.println("     testLinks events (" + test.batches + " batch(es), thread " + test.thread + "): " + test.events);
        check(test.count("result") == 2, "one result per link");
        check(test.events.stream().anyMatch(e -> e.contains("\"delay_ms\":-1") && e.contains("\"error\"")),
                "unreachable link -> delay_ms -1 with error");
        check(ZrayNative.PROTECT_CALLS.get() > protectBefore,
                "Rust called ZrayNative.protect for the test socket (from thread '" + ZrayNative.lastProtectThread + "')");

        // ---- cancel a long job
        Collector longJob = new Collector();
        String silent = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@192.0.2.1:443#blackhole";
        long longHandle = ZrayNative.testLinks("{\"links\":[\"" + silent + "\"],\"timeout_ms\":30000}", longJob);
        check(longHandle > 0 && longHandle != handle, "second job gets its own handle " + longHandle);
        Thread.sleep(300);
        long cancelledAt = System.nanoTime();
        ZrayNative.cancel(longHandle);
        check(longJob.done.await(5, TimeUnit.SECONDS), "cancel(handle) -> done arrives");
        long cancelMs = (System.nanoTime() - cancelledAt) / 1_000_000;
        check(longJob.events.stream().anyMatch(e -> e.contains("\"reason\":\"cancelled\"")),
                "done reason is cancelled (" + cancelMs + " ms after cancel)");
        ZrayNative.cancel(longHandle);
        ZrayNative.cancel(999_999);
        check(true, "cancelling finished/unknown handles is harmless");

        // ---- immediate failure: handle 0 and a single error event
        Collector broken = new Collector();
        long zero = ZrayNative.discover("{not json", broken);
        check(zero == 0, "discover(bad json) -> 0");
        check(broken.any.await(5, TimeUnit.SECONDS) && broken.count("error") == 1,
                "discover(bad json) delivers one error event: " + broken.events);

        // ---- discover with nothing to do, and scan with an unknown preset
        Collector empty = new Collector();
        long discoverHandle = ZrayNative.discover("{\"fetch\":false,\"max_seconds\":5}", empty);
        check(discoverHandle > 0 && empty.done.await(10, TimeUnit.SECONDS), "discover(empty) -> done");
        check(empty.events.stream().anyMatch(e -> e.contains("\"reason\":\"exhausted\"")), "discover(empty) exhausted");
        Collector scan = new Collector();
        long scanHandle = ZrayNative.scan("{\"preset\":\"nope\"}", scan);
        check(scanHandle > 0 && scan.done.await(10, TimeUnit.SECONDS) && scan.count("error") == 1,
                "scan(unknown preset) -> error then done");

        System.out.println("\nALL " + checks + " CHECKS PASSED");
        System.exit(0);
    }
}
