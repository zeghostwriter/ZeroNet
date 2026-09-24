# ZrayNative — the Kotlin ↔ Rust contract

This is the only boundary between the app and Zray-Core. The Rust side lives
in `Zray-Core/crates/zray-mobile/src/android.rs` (feature `jni`), with the
discovery engine in `Zray-Core/crates/zero-discovery`. The Kotlin side is
`app/src/main/java/com/zeronet/mobile/core/ZrayNative.kt`.

## Rules

- Library name: `libzray_mobile.so` → `System.loadLibrary("zray_mobile")`.
- All data crosses as **UTF-8 JSON strings**. No JNI object graphs.
- **No function may panic across JNI.** Every export catches unwinds and
  returns an error value.
- **No function blocks the caller longer than ~1 s** except `start`, `reload`
  and `stop`, which the service calls off the main thread. Long work (discovery,
  scanning, delay tests) runs on Rust-owned threads and reports through a
  listener.
- Listener callbacks arrive on Rust threads, **batched**. Each call carries one
  or more newline-separated JSON events, at most ~10 calls/s. Kotlin must not
  block inside a callback.
- Errors are returned as `String?` (null = success) or as `{"error": "..."}`
  inside a JSON result.

## Kotlin declaration

```kotlin
package com.zeronet.mobile.core

fun interface NativeListener { fun onEvents(batch: String) }

object ZrayNative {
    init { System.loadLibrary("zray_mobile") }

    /** Once per process. dataDir is filesDir; logs go to dataDir/zray.log (size-capped) and logcat tag "zray". level: off|error|warn|info|debug */
    @JvmStatic external fun init(dataDir: String, logLevel: String): String?

    // ---- runtime (VPN process)
    @JvmStatic external fun setTun(fd: Int, mtu: Int): String?
    @JvmStatic external fun start(configJson: String): String?
    /** Swap config without dropping the TUN. Existing sessions finish on the old generation. */
    @JvmStatic external fun reload(configJson: String): String?
    @JvmStatic external fun stop(): String?
    @JvmStatic external fun isRunning(): Boolean
    /** {"up":u64,"down":u64,"sessions":u64,"tags":{"<tag>":{"up":u64,"down":u64}}} or null */
    @JvmStatic external fun stats(): String?
    /** Drop the DNS cache and the resolver's pooled connections after the underlying network changed. */
    @JvmStatic external fun networkChanged(): String?

    // ---- config
    /** BuildRequest JSON → {"config": {...}} | {"error": "..."} */
    @JvmStatic external fun buildConfig(requestJson: String): String
    /** Any text (links, base64 subscription, mixed) → {"items":[LinkInfo...],"rejected":n,"reasons":{"<reason>":n}} */
    @JvmStatic external fun parseLinks(text: String): String
    //   (also "duplicates": n — links dropped because an earlier one had the same key)

    // ---- long-running jobs; return a handle (>0) or 0 on immediate failure (a single error event is still delivered)
    @JvmStatic external fun discover(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun testLinks(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun scan(requestJson: String, listener: NativeListener): Long
    @JvmStatic external fun cancel(handle: Long)

    /** Called BY Rust for every outbound socket. Implemented in Kotlin; routes to the live VpnService. */
    @JvmStatic fun protect(fd: Int): Boolean = SocketProtection.protect(fd)
}
```

`protect` is installed once per process with `zero_core::set_socket_protector`.
The Rust protector attaches the current thread to the cached `JavaVM`, calls
the static `protect(I)Z`, and treats `false` or an exception as failure. If no
`VpnService` is live, Kotlin returns `true`.

## LinkInfo

```json
{"key":"<16-hex stable hash of the normalized link without #remark>",
 "link":"vless://...","name":"remark or host","protocol":"vless|vmess|trojan|ss|hysteria2|tuic|anytls",
 "transport":"tcp|ws|grpc|xhttp|httpupgrade|quic|...","security":"none|tls|reality",
 "host":"example.com","port":443,"country":"",
 "class":"xhttp_extra|reality|cdn|other" }
```

- `key`: first 16 hex digits of BLAKE3 over the link with the `#remark`
  removed, trimmed, and `&amp;` unescaped. Renaming a server keeps its key.
- `country` is an ISO-3166 alpha-2 guess from a flag emoji, an upper-case
  two-letter code token (`[DE]`, `US-1`) or an English country name in the
  remark. Empty if unknown.
- `class` is the family discovery interleaves by: `xhttp_extra` (XHTTP with a
  non-empty `extra` query parameter), `reality`, `cdn` (TLS over
  WebSocket/gRPC/HTTPUpgrade), `other`.
- `transport` is `quic` and `security` is `tls` for hysteria2/tuic.
- Parsing accepts plain lists, base64 subscription bodies, links embedded in
  prose/HTML and several links per line. Non-proxy URLs are ignored, not
  rejected. `reasons` keys are `<scheme>:<malformed|invalid|unsupported>`.

## BuildRequest (buildConfig)

```json
{
  "links": ["vless://...", "..."],
  "mode": "vpn" | "proxy",
  "tun": {"mtu": 1500, "ipv6": false},
  "socks_port": 10808, "http_port": 10809,
  "lan": {"enabled": false, "listen": "0.0.0.0", "user": "", "pass": ""},
  "iran_direct": true, "block_ads": true, "block_quic": true,
  "evasion": "off" | "auto" | "strong",
  "dns": {"remote": "google", "custom": "", "local": "google", "fakedns": true},
  "log_level": "warning",
  "clean_ips": ["104.16.1.2:443"]
}
```

Every field is optional except `links`. Defaults are the values shown, except
`clean_ips` (empty) and `lan.enabled` (false). `dns.remote`:
cloudflare|google|quad9|adguard; `dns.local`: google|cloudflare|system.
`dns.custom` (empty by default) is a user-supplied resolver that overrides
`dns.remote` for the encrypted "everything else" tier when non-empty: any form
`ResolverEndpoint::parse` accepts (a bare IP like `8.8.8.8`, `tls://…`,
`https://…/dns-query`, …). An unparseable value returns `{"error": …}`.

**Output.** A complete Zray config built on `zero_config::IranPreset`, plus:

- **Inbounds.**
  - `socks-in` and `http-in` on 127.0.0.1.
  - When `lan.enabled`, the same two inbounds bind `lan.listen` instead, with
    optional user/pass. **Deviation:** the runtime's HTTP inbound has no
    authentication, so when `lan.user` is set only `socks-in` binds
    `lan.listen` (with password auth); `http-in` stays on 127.0.0.1 rather
    than exposing an open proxy next to a protected one.
  - In `vpn` mode, a `tun` inbound tagged `tun-in` with sniffing on. Its
    addresses match what Kotlin gives `VpnService.Builder`:
    `172.19.0.1/30`, plus `fdfe:dcba:9876::1/126` with IPv6.
- **Outbounds.**
  - The first link is tagged `proxy`; the rest are `proxy-1..n`.
  - With more than one link, a balancer `auto` (strategy `leastPing`) over
    the `proxy*` selector, with the observatory probing
    `https://www.gstatic.com/generate_204` every 60 s. The final routing rule
    sends to the balancer.
- **Routing.**
  - UDP/53 from `tun-in` → a `dns-out` (protocol `dns`) outbound. The runtime
    answers these queries itself (`zero_runtime::dns_out`, added for this):
    A/AAAA through Zray's tiered resolver (anti-sanction → local for Iranian
    names → encrypted remote), every other type an empty NOERROR, TTL 60 s.
    Any DNS server address Kotlin gives `VpnService.Builder.addDnsServer`
    works as long as it is routed into the TUN (the app's `1.1.1.1` with a
    default route is fine): the rule matches port 53 from `tun-in`, not an
    address.
  - Without `tun.ipv6`, `dns.queryStrategy` is `UseIPv4`, so AAAA questions
    are answered empty and apps never try a family the tunnel cannot carry.
  - Iran domains/IPs direct when `iran_direct` is on. When it is off, private
    ranges (`geoip:private`) still go direct.
  - QUIC (UDP 443) to non-Iran blocked when `block_quic` is on (the rule
    follows the Iran-direct rules).
  - `clean_ips` (scanner results, `ip:port`) become the preset's
    `clean_ip_candidates`: the observatory measures them against
    `www.speedtest.net` and ranks edges for CDN-fronted outbounds.
- **FakeDNS is not emitted** (`dns.fakedns` is accepted and ignored). The
  runtime has one resolver for everything, including its own lookups of proxy
  server names, so a catch-all FakeDNS server would hand the dialer synthetic
  198.18.0.0/15 addresses for the proxy servers themselves.
- **Evasion.**
  - `strong` fragments the ClientHello on every TLS/REALITY link (not on ECH
    or plaintext links, where it is invalid or pointless).
  - `auto` leaves it to the planner.
  - `off` adds nothing. The runtime's planner is internal and has no config
    switch, so `off` and `auto` currently produce the same config.
- **Assets.** Managed (geoip/geosite) only if both `geosite.dat` and
  `geoip.dat` exist in `dataDir/assets` (`dataDir` from `init`). Otherwise
  the domain-list fallback (`IRAN_DIRECT_DOMAINS`) is used; `geosite:`/`geoip:`
  selectors without data simply never match.
- The result must pass `zero_config::compile_config`. If not, return
  `{"error": <compiler message>}`.

## DiscoverRequest (discover)

```json
{
  "sources": [{"id":"limilco","url":"https://raw.githubusercontent.com/.../new_configs.txt","tier":1}],
  "cache_dir": "/data/.../cache/feeds",
  "priority_links": ["..."],
  "extra_links": ["..."],
  "exclude_keys": ["..."],
  "want_alive": 5, "max_seconds": 60,
  "tcp_concurrency": 256, "tcp_timeout_ms": 1500, "tcp_stop_after_open": 400,
  "real_concurrency": 24, "real_timeout_ms": 4000,
  "probe_url": "http://cp.cloudflare.com/generate_204",
  "confirm_tls": true,
  "next_tier_if_alive_below": 3,
  "fetch": true,
  "fetch_timeout_ms": 20000
}
```

All fields are optional (defaults as shown; `sources`, `cache_dir` and the
link lists default to empty). Values are clamped to sane ranges.

- `priority_links` are the history winners for this network. They are tested
  first.
- `extra_links` are the user's own configs.

**Algorithm.**
1. Real-test `priority_links` (skip TCP).
2. If `fetch`, fetch tier 1 feeds:
   - gzip;
   - ETag/Last-Modified cached in `cache_dir/<id>.meta`, body in
     `cache_dir/<id>.txt`;
   - on 304, or on network failure with a cache present, use the cache.
3. Parse with `zero_config::parse_subscription` and dedupe by `key`.
4. Order candidates: round-robin across classes (xhttp+extra /
   reality / cdn-ws-tls / other), random within a class.
5. TCP stage, then real stage, streaming. One TCP connect answers for every
   link sharing a `host:port`; hysteria2/tuic (UDP) skip the TCP stage. The
   TCP stage stops launching after `tcp_stop_after_open` open ports per tier.
6. Once tier 1 is exhausted with fewer than `next_tier_if_alive_below` alive,
   fetch the next tier and repeat.
7. Stop at `want_alive`, when all tiers are exhausted, at `max_seconds`, or
   on cancel.

**Real test.**
1. Parse the link to a `zero_config::Outbound` and validate it.
2. `zero_runtime::outbound::connect(outbound, dest)` to the probe URL's host
   and port. `probe_url` must be `http://` (an HTTPS probe is refused).
3. Send `GET <path> HTTP/1.1`. Success is status 200–399; delay is the time to
   the status line.
4. Do it twice and report the smaller delay, but only if the first succeeded.

**Events** (newline-separated JSON objects):

```json
{"t":"stage","stage":"history|fetch|parse|tcp|real"}
{"t":"source","id":"limilco","status":"ok|cached|not_modified|error","count":123,"bytes":45678,"error":"..."}
{"t":"progress","candidates":4200,"tcp_done":800,"tcp_open":230,"real_done":60,"alive":2}
{"t":"alive","info":{LinkInfo},"delay_ms":312}
{"t":"done","alive":5,"reason":"enough|exhausted|timeout|cancelled","elapsed_ms":8123}
{"t":"error","message":"..."}
```

- `stage` events: `history` (before the priority links), then per tier
  `fetch`, `parse`, `tcp`, and `real` when the first candidate reaches the
  real stage.
- `source.error` is present only when the status is not `ok`.
- `progress` is emitted on a 500 ms tick only when a counter changed, and once
  more right before `done`.
- An `alive` key is reported once even when several feeds list it.
- `done` is always the last event of a job.

## TestRequest (testLinks)

```json
{"links":["..."],"concurrency":16,"timeout_ms":4000,"probe_url":"http://cp.cloudflare.com/generate_204","tcp_only":false,"confirm_tls":true}
```

Events:

```json
{"t":"result","key":"...","delay_ms":312}
{"t":"result","key":"...","delay_ms":-1,"error":"..."}
{"t":"done","alive":1,"tested":2,"reason":"exhausted|cancelled","elapsed_ms":2}
```

Every link produces exactly one `result` (an unparseable link too, keyed by
the same hash, with `error` starting `parse:`). `tcp_only` times the TCP
handshake to the server; for hysteria2/tuic it reports an error.

## ScanRequest (scan)

```json
{"preset":"cloudflare","ports":[443,2053,8443],"host":"www.speedtest.net","count":2000,"concurrency":128,"timeout_ms":1500}
```

Events:

```json
{"t":"progress","scanned":n,"responsive":m,"total":t}
{"t":"ip","ip":"104.x.x.x","port":443,"rtt_ms":82}
{"t":"done","scanned":n,"responsive":m,"reason":"exhausted|cancelled","elapsed_ms":t}
```

Uses `zero-scanner` (`ScanEngine`/`Prober`) against the Cloudflare ranges, in
TLS mode (TCP connect + a handshake with SNI `host`, two tries), IPv4 only.
One engine per port shares one address source, so `count` is split across the
ports and each port probes different addresses; neighbours of a responsive
address are probed next. `rtt_ms` is the best try. Only `preset:"cloudflare"`
exists; anything else is an `error` event followed by `done`.

## Runtime notes (Rust side)

- **`init`** logs to `dataDir/zray.log`, rotated to `zray.log.1` at 2 MB, and
  (on Android) to logcat tag `zray`. Calling it again only changes the level.
  It caches the `JavaVM` and the `ZrayNative` class + `protect(I)Z` method id
  and installs the socket protector (once per process).
- **`start`/`reload`/`stop`** are the C ABI's `zray_start`/`zray_reload`/
  `zray_stop`. `stop` when nothing runs returns an error string. `reload`
  cannot change the inbound topology (listeners, ports, protocols, the TUN
  inbound); that is an error string and needs stop + start.
- **`stats`**: `up`/`down` are totals over every session the runtime carried
  (proxied and direct); `sessions` is the number of live TCP sessions; `tags`
  holds per-inbound and per-outbound byte counts keyed by tag (tags only
  appear once they carried traffic).
- **`networkChanged`** re-installs the current config as a new generation:
  the resolver is replaced, which drops the DNS cache and its pooled DoH/DoT
  connections. Live sessions are not killed; dead ones fail on their own and
  apps re-dial. Returns null when nothing is running. Also exported to C as
  `zray_network_changed`.
- **Threads.** The proxy runtime uses `min(cores, 3)` workers named `zray-rt`.
  Jobs share a separate runtime with 2 workers named `zray-jobs`, whose
  threads attach to the VM as daemons at start. Listener batches are
  delivered from that runtime's blocking pool.
- **Job failures.** A job that cannot start returns 0 after delivering one
  `error` event. A job that panics internally delivers an `error` event and a
  `done` with `"error":true`.
- **Build.** `Zray-Core/crates/zray-mobile/build-android.sh <jniLibs dir>`
  builds arm64-v8a, armeabi-v7a and x86_64 (API 30) with the
  `release-mobile` profile: release with `panic = "unwind"`, which the
  catch-unwind guards need (the workspace `release` profile aborts on panic).
  cargo-ndk 4 takes the API level as `-P 30` (not `-p`, which is cargo's
  `--package`).

## Liveness: TLS confirmation (added 2026-09-24)

A config counts as alive only if **both** of these pass:

1. The plain-HTTP probe (`probe_url`), which is a cheap filter.
2. A verified HTTPS `GET https://www.gstatic.com/generate_204` through the
   same outbound (`confirm_tls`, default `true`).

**Why.** Measured from inside Iran, configs that passed the plain probe went
on to fail every real request, including TLS. A plain 204 can come from
something other than the internet; a certificate-verified handshake with the
real host cannot. `delay_ms` is still the plain request's time.

**Per-tier TCP budget.** `tcp_stop_after_open` applies to each tier. Before
this fix it was cumulative, so later tiers stopped at their first candidate.
