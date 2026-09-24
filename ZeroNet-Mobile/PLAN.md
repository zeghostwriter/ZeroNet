# ZeroNet Mobile — implementation plan (v2)

Revised 2026-09-23. v1 set up the fork; v2 answers three things:

1. **Where configs come from**, backed by measurements taken *from inside
   Iran* through Zray-Core itself (§3).
2. **How the app stays fast and light**: startup, frame time, battery, memory,
   mobile data and time-to-connected (§5).
3. **What it looks and feels like.** A VPN app built around one big connect
   orb. It must not feel like v2rayNG anywhere, settings included (§6).

Inputs: v2rayNG 2.2.6 source, the Zray-Core workspace in `..`, 26 candidate
GitHub feeds, a live in-Iran test harness, and current Android/Compose
documentation.

---

## 1. Product in one paragraph

Open the app and tap the orb. ZeroNet pulls fresh community configs from
GitHub. It tests them in stages on *your* network and connects to the first
one that really carries traffic, usually within seconds. It keeps testing in
the background and quietly moves you to a faster server if it finds one.
Everything else (servers, sharing, the clean-IP scanner, settings) is one tap
away in a bottom bar, and nothing asks the user to understand what VLESS or
REALITY means.

---

## 2. What we keep from v2rayNG and what we replace

Once the UI is replaced, the core is swapped and discovery moves to Rust,
v2rayNG contributes plumbing, not experience.

| Keep and adapt | Replace completely |
|---|---|
| `VpnService` setup (`CoreVpnService`: routes, DNS, MTU, per-app, always-on) | All screens, the navigation model, settings, dialogs, notifications' look |
| Foreground service declarations (`specialUse`), QS tile, boot receiver | The profile store for discovered configs (MMKV JSON per profile → Room, §5.4) |
| Import formats (`fmt/`: Clash, sing-box JSON, custom configs) | Speed test / real-ping workers (→ Rust pipeline) |
| Xray JSON builder (`CoreConfigManager`, `CoreOutboundBuilder`) as the source of Zray configs | `libv2ray` (Go) and `hev-socks5-tunnel` → `libzray_mobile.so` |
| Routing rule-set handling | Gson → kotlinx.serialization (no reflection, smaller, faster) |

License stays GPL-3.0. Zray-Core is MPL-2.0, which is GPL-compatible.

---

## 3. Config sources — measured, not guessed

### 3.1 Method

All numbers were measured on 2026-09-23 from a residential connection in
Iran. Cloudflare's trace reported `loc=IR`, so this is the network the app
will actually run on.

1. Downloaded each feed's main file from `raw.githubusercontent.com`.
2. Parsed every link with **Zray's own parser** (`zray check`).
3. **TCP stage**: connected to each config's server (≤1,500 per feed,
   2.5 s timeout).
4. **Real stage**: picked up to 100 TCP-open configs at random. For each one,
   `zray preset iran <link>` → `zray run` → `curl` through its SOCKS port to
   `https://cp.cloudflare.com/generate_204`. A config is *alive* only if the
   204 response came back through the tunnel.
5. **Cross-check**: the same links were run through the **Xray 26.7.28**
   oracle: 210 TCP-open links from PSG, 0xRadikal, barry-far and Delta.
   Xray found 2 alive, Zray 1. So the low yields are Iranian filtering, not
   Zray. The one difference is a Zray bug listed in §3.6.

The harness is committed in [`tools/feed-eval/`](tools/feed-eval/). In
phase 3 it becomes a scheduled job run from an Iranian vantage point that
re-ranks `sources.json` (§3.5).

### 3.2 Results

Measured 2026-09-23 from inside Iran. **Parse** = links Zray accepts.
**TCP** = share of sampled configs whose server port answered. **Alive** =
real end-to-end success through Zray over randomly chosen TCP-open configs.
**Covers** = how many of the 8 distinct working servers found across *all*
feeds this feed contains.

| Feed (GitHub) | ★ | File | gzip | Parse | TCP | Alive | Covers |
|---|---:|---|---:|---:|---:|---:|---:|
| `0xRadikal/Free-v2ray-Configs` | 628 | `all/configs.txt` | 642 KB | 84% | 35% | **6/100** | **8/8** |
| `liMilCo/v2r` | 68 | `new_configs.txt` | **213 KB** | 77% | 19% | 2/100 | **7/8** |
| `SoliSpirit/v2ray-configs` | 618 | `all_configs.txt` | 786 KB | 77% | 21% | 0/100 | 7/8 |
| `mheidari98/.proxy` | 188 | `all` | 1,699 KB | 77% | 14% | 1/100 | 7/8 |
| `ebrasha/free-v2ray-public-list` | 1,313 | `V2Ray-Config-By-EbraSha-All-Type.txt` | 1,501 KB | 77% | 30% | 0/100 | 7/8 |
| `Epodonios/v2ray-configs` | 3,250 | `All_Configs_Sub.txt` | 267 KB | 83% | 34% | 0/40* | 6/8 |
| `barry-far/V2ray-Config` | 2,456 | `All_Configs_Sub.txt` | 330 KB | 83% | 33% | 1/100 | 6/8 |
| `Delta-Kronecker/V2ray-Config` (Xray-tested) | 343 | `config/all_configs.txt` | 370 KB | 67% | 38% | 1/100 | 5/8 |
| `Argh94/V2RayAutoConfig` | 357 | `configs/Vless.txt` | 1,028 KB | 70% | 33% | 0/100 | 5/8 |
| `hamedcode/port-based-v2ray-configs` | 131 | `sub/port_443.txt` | 522 KB | 38% | 37% | 1/100 | 4/8 |
| `MhdiTaheri/V2rayCollector` | 317 | `sub/mix` | 90 KB | 42% | 33% | 0/100 | 4/8 |
| `ALIILAPRO/v2rayNG-Config` | 361 | `sub.txt` | 266 KB | 81% | 29% | 0/100 | 3/8 |
| `4n0nymou3/multi-proxy-config-fetcher` | 98 | `configs/proxy_configs_tested.txt` | 11 KB | 88% | 12% | **2/25** | 1/8 |
| `sinavm/SVM` | 433 | `lite/subscriptions/xray/base64/mix` | 8 KB | 64% | 9% | **2/6** | 2/8 |
| `F0rc3Run/F0rc3Run` | 304 | `Best-Results/sub.txt` | 48 KB | 88% | 18% | 1/76 | 2/8 |
| `MatinGhanbari/v2ray-configs` | 667 | `subscriptions/v2ray/all_sub.txt` | 283 KB | 62% | 18% | 0/100 | 2/8 |
| `itsyebekhe/PSG` | 443 | `subscriptions/xray/mix` | 24 KB | 80% | 76% | 0/100 | 1/8 |
| `mahdibland/V2RayAggregator` | 4,018 | `sub/sub_merge.txt` | 145 KB | 48% | 2% | 0/34 | 1/8 |
| `ShatakVPN/ConfigForge-V2Ray` | 359 | `configs/de/all.txt` | 14 KB | 76% | 29% | 0/61 | 1/8 |
| `V2RayRoot/V2RayConfig` | 170 | `Config/vless.txt` | 18 KB | 82% | 40% | 0/87 | 0/8 |
| `Kolandone/v2raycollector` | 62 | `config_lite.txt` | 3 KB | 58% | 6% | 0/2 | 0/8 |
| `NiREvil/vless` | 1,333 | `edge/assets/p-all.txt` | — | 0% | — | — | not share links (endpoint list) |

\* Epodonios was measured in the first, lowest-latency-first run, where it
went 0/40. Its content is ~99.9% identical to barry-far (same generator), so
treat the two as one source.

### 3.3 What the data says

- **Stars do not predict usefulness.** mahdibland (4,018★) is mostly
  Shadowsocks aimed at China and almost nothing on it is reachable from Iran.
  PSG answers TCP 76% of the time but carried nothing end-to-end.
- **Yields are tiny: 0–6% of TCP-reachable configs work**, confirmed with the
  Xray oracle on 210 links: Xray 2 alive, Zray 1. The one Zray missed is
  a real Zray bug (§3.6, XHTTP `extra`). This is why the engine races for
  the first good config (§4) instead of ranking everything.
- **A TCP ping is nearly worthless as a filter.** 20–76% of configs accept
  TCP, but almost none carry traffic, because filtering happens after the
  handshake. The real stage decides.
- **Working servers are few and shared.** All 17 working links were 8
  servers, repeated across aggregators:
  - 3 × VLESS REALITY (two on :443);
  - 3 × **CDN-fronted WS+TLS on Fastly** (151.101.x, 199.232.x), a class the
    app must treat like Cloudflare-fronted configs;
  - 1 × Shadowsocks;
  - 1 × plain VLESS-WS.

  No single class dominates, so the engine tests across classes rather than
  betting on one.
- **Aggregators overlap heavily.** The 16 largest feeds hold 42.5k unique
  endpoints. Epodonios/barry-far are identical. Only ebrasha, mheidari and
  0xRadikal carry many exclusive endpoints. Fetching many feeds mostly
  re-downloads the same configs.
- **"Listed in many feeds" is not a useful signal.**
  - The working servers appeared in 2–14 feeds each, which looked
    promising.
  - A stratified test (120 random TCP-open servers each from the "1 feed"
    and "≥5 feeds" groups) gave **1 alive in both**. The apparent effect was
    a sampling artifact.
  - The engine does not use it. Only per-network history is a proven
    prior.
- **Caveat:** one afternoon, one residential ISP, samples of ≤100 per feed.
  Iran's filtering changes daily. The source list must be re-measured
  continuously, which is why `tools/feed-eval` becomes a scheduled job run
  from an Iranian vantage point that updates `sources.json` (§3.5).

### 3.4 Feed set shipped by default

Tiered, so the common case downloads very little:

| Tier | Feeds | gzip total | When fetched |
|---|---|---:|---|
| 0 | Cached winners for this network | 0 | Every connect, first |
| 1 | `liMilCo/v2r` `new_configs.txt`, `sinavm/SVM` lite mix, `4n0nymou3` tested list | ~232 KB | Cold connect (ETag makes repeats ~free) |
| 2 | `0xRadikal/Free-v2ray-Configs` `all/configs.txt`, `Epodonios/v2ray-configs` `All_Configs_Sub.txt` | ~909 KB | Only if tier 1 yields < 3 alive |
| 3 | `Delta-Kronecker/V2ray-Config`, `mheidari98/.proxy`, `F0rc3Run` Best-Results | ~2.1 MB | Only on explicit "search harder" or Wi-Fi |

- Tier 1 + 2 together cover **8/8** of the working servers found. Tier 1
  alone covers 7/8 for about a quarter of a megabyte.
- **Epodonios is in tier 2 because it is the most widely used Iranian
  feed.** barry-far is omitted as its duplicate.
- Users can enable any feed from the table in *Settings → Servers & sources*,
  and add their own subscriptions.

### 3.5 How the app fetches (efficient by construction)

- **GitHub raw only**, as requested. `raw.githubusercontent.com` serves
  **gzip** (Barry-Far's 1.9 MB list arrives as 338 KB) and supports **ETag**
  (`If-None-Match` → `304`, 0 bytes). The app always sends both, so an
  unchanged feed costs one tiny round-trip.
- **Conditional refresh.** Refresh when the user taps connect and the cache
  is older than 15 minutes (feeds regenerate every 15–60 min), or on
  pull-to-refresh. There is **no periodic background fetching**.
- **Streaming parse** in Rust. Links are parsed as the gzip stream is
  inflated, so a 9 MB list never sits in memory as one string. Duplicates are
  dropped by a 64-bit hash of (scheme, host, port, id, transport, path, sni).
- **The default source list is a JSON file in this repo** (`sources.json`,
  signed with ed25519, key pinned in the app). A feed that dies or turns bad
  is replaced with a commit, with no app update needed. The app falls back to
  the copy bundled in the APK.
- **Per-network memory.** Configs that worked are remembered per network
  (Wi-Fi SSID hash, or carrier: MCI, Irancell, Rightel via
  `lookup_iranian_isp`). The next connect tests those first and usually
  succeeds without fetching anything.

### 3.6 Zray-Core compatibility bugs (differential vs Xray, from Iran)

Full report, root causes and repro links:
`../local/zray-compat-bugs/README.md`. It is gitignored because the repro
links contain third-party credentials. Headlines:

| Bug | Kind | Proven in Xray from Iran |
|---|---|---|
| XHTTP `extra` obfuscation fields (`xPaddingObfsMode`, `sessionIDPlacement`, `seqPlacement`, …) ignored | silent (parses, never connects) | **39/80** of XHTTP+extra/TLS; Zray 0 |
| XHTTP over REALITY never connects | silent | **10/46** + 3/3; Zray 0/9 |
| Shadowsocks `2022-blake3-chacha20-poly1305` | rejected | **11/15** |
| VLESS ML-KEM encryption | rejected | 2/54 |
| REALITY over gRPC | rejected | 1/40 |
| VMess `type`/`aid`, non-UUID IDs, REALITY empty `fp`, TLS `fp=unsafe`, Vision over non-raw | rejected, Xray accepts | not alive from here today |
| REALITY servers with ML-DSA-65 | silent, suspected | 1 server |

`allowInsecure` is *not* a bug: Xray removed it too.

**Why this matters for the app.** Measured through Xray, XHTTP with `extra`
is the highest-yield class in Iran right now: roughly half of TCP-reachable
configs work, against ~1% elsewhere. With bugs 01–02 fixed, the discovery
engine should test this class first. Cold time-to-connected would drop from
"hundreds of probes" to "a handful". So fixing 01–03 in Zray is **phase 2's
first task**, ahead of the JNI work.

## 4. Discovery engine — "Fastest" in seconds, not minutes

Yields are around 1–2%. So the engine is built to **find the first good config
fast, then improve**, not to rank everything before connecting.

```
tap ─► cached winners for this network (≤10) ── real test ──► connect (typically < 2 s)
        │ none alive
        ▼
       fetch feeds (ETag/gzip) ─► parse+dedupe (Rust, streaming)
        ▼
       order: per-network history first, then round-robin across classes
              (XHTTP+extra first once Zray supports it · REALITY · CDN-fronted
              WS · other), random within
        ▼
       TCP stage: 256 in flight, 1.5 s timeout, stop at 400 open
        ▼
       real stage: 24 in flight, 3 s timeout, *in-process*, no subprocess
        ▼  first alive ─► CONNECT immediately
       continue until 5 alive or 60 s ─► Zray balancer (leastPing) over them
        ▼
       background: observatory health checks; better one found ─► zray_reload
```

- **In-process real tests.** A new ABI entry,
  `zray_measure_delay(json, url, timeout)`, builds an outbound in the running
  tokio runtime and fetches `generate_204` through it. No second runtime, no
  sockets on localhost, no processes.
  - Before connecting, test sockets need no protection.
  - After connecting, they are protected, so tests go *around* the tunnel and
    measure the direct path.
- **Hot swap, no TUN teardown.** `Server::reload` already swaps the config
  generation atomically (`ArcSwap`). Expose it as `zray_reload(json)`.
  Switching servers then never drops the VPN interface. Existing connections
  finish on the old outbound, new ones use the new one.
- **Failover inside Zray.** Connect with a **balancer** over the 3–5 alive
  configs, plus the observatory (both exist in Zray). A dying server is
  routed around in-process within one probe interval, and Kotlin is not
  involved.
- **Scoring** = p50 delay, jitter over 3 samples, success history on this
  network (exponential decay, 24 h half-life), and class bonuses. Stored in
  Room so the next connect starts from it.
- **Budget.** A cold discovery must stay under **3 MB of mobile data** and
  **60 s of worst-case CPU at <25% of one core**. Early exit keeps the common
  case far below that.

---

## 5. Performance and efficiency of the app itself

The rule: **the UI process is thin, the VPN process is native, and nothing
polls.**

### 5.1 Process and threading model

| Process | Contains | Memory target (PSS) |
|---|---|---|
| `:ui` (main) | Compose UI, Room reads, view models. **Never loads `libzray_mobile.so`.** | < 60 MB idle on Home |
| `:vpn` | `ZeroVpnService`, a tiny Kotlin shim (no Compose, no DI framework), Zray runtime, discovery, scanner | < 35 MB connected, idle traffic |

- **IPC:**
  - Service → UI: a bound `Messenger`/AIDL interface that pushes a
    compact `ConnState` binary parcel on change.
  - Stats: pushed at **1 Hz, only while a UI client is bound and resumed**.
    Zero IPC when the screen is off.
- **Tokio runtime:**
  - `worker_threads = min(cores, 3)`.
  - Named threads, 512 KB stacks.
  - `event_interval` tuned so timers don't wake idle cores.

  Today `zray-mobile` uses the default multi-thread runtime, which starts one
  worker per core (8 on most phones) and wakes more often than needed.
- **Allocator:** evaluate `mimalloc` against Android's Scudo for the proxy
  data path. Adopt it only if the benchmark (§5.7) shows ≥10% throughput or
  CPU gain.

### 5.2 Data path

- **MTU.**
  - Benchmark 1500 against 9000 (sing-box's Android default) on the TUN.
  - A larger MTU means fewer packets through smoltcp and fewer syscalls, so
    lower CPU per MB.
  - Keep 1500 if it wins on cellular.
- **TUN reads.** `zero-tun` uses `AsyncFd`. Drain the descriptor until
  `EAGAIN` on every wake-up (batching), and reuse packet buffers from a pool
  so there is no allocation per packet.
- **FakeDNS by default in TUN mode.** Zray supports it (`ResolverEndpoint::
  FakeDns`). It removes a DNS round-trip through the tunnel from every new
  connection, which matters on 150–300 ms Iranian mobile RTTs. Iranian
  domains stay on real DNS for direct routing.
- **Network changes.**
  - `ConnectivityManager.NetworkCallback` → `zray_network_changed()`, which
    drops stale sockets and the DNS cache and re-dials.
  - Call `setUnderlyingNetworks()` so Android attributes battery and data
    correctly and hands over between Wi-Fi and cellular without a restart.
- **UDP/QUIC.** Block QUIC to non-Iranian destinations when the outbound
  cannot carry UDP well, so apps fall back to TCP instead of timing out.
  This is the standard trick, and it avoids long stalls.

### 5.3 Battery

- **No wakelocks, no alarms, no WorkManager periodic jobs.** The only
  periodic work is observatory probing, which:
  - backs off from 30 s to 5 min while traffic is idle;
  - pauses under Doze;
  - resumes on the first packet.
- **UI animations stop when not visible.** Infinite transitions are keyed to
  `Lifecycle.State.RESUMED`. The notification's speed text updates at most
  every 2 s and never while the screen is off.
- **Measured with** `dumpsys batterystats` plus Perfetto power rails on a Pixel.
  - Target: **≤ 2%/h additional drain** idle-connected.
  - Target: **≤ 5%/h** while streaming 1080p.

### 5.4 Storage

- **Room (SQLite)** for configs, sources, test history and per-network scores.
  - Indexes on `(network_id, score)` and `hash`.
  - The Servers list is a paged `Flow`.
  - v2rayNG's approach of one JSON blob per profile in MMKV makes listing
    thousands of entries O(n) deserialization and is replaced.
- **Retention.** Keep at most 2,000 discovered configs. Evict by score and
  age. Winners are never evicted.
- **MMKV** stays for small settings (fast, mmap), read once at start into an
  immutable settings object.

### 5.5 UI performance

- **Draw-phase animation only.**
  - The connect orb is one `Canvas` using `drawWithCache`.
  - Ring phase and arc angle are read *inside the draw lambda* from
    `Animatable`/`withFrameNanos` state, so every frame is draw-only with
    **zero recompositions**.
  - Offsets use lambda modifiers (`Modifier.offset { }`,
    `graphicsLayer { }`).
- **Lists.**
  - Stable keys, `@Immutable` UI models, `contentType`, and `derivedStateOf`
    for sort/filter.
  - Compose 1.10+ pausable composition in lazy prefetch is on by default.
    Add a `LazyLayoutCacheWindow` for smoother fast flings through 2,000
    rows.
  - Ping chips update through a per-row `State`, so a new result recomposes
    one chip, not the list.
- **Glass is budgeted.**
  - Haze 2.0 with `HazePerformanceMode.Adaptive` and `inputScale = 0.5`.
  - Applied on **three surfaces only** (bottom bar, connect sheet, scrolled
    top bar).
  - Uses the native backdrop `RenderEffect` on Android 17 QPR2+.
  - Below API 31, a tinted opaque surface.
  - Glass is disabled automatically when battery saver is on.
- **Startup.**
  - No `Application.onCreate` work beyond a crash handler.
  - Settings load off-main.
  - Room opens lazily.
  - Splash Screen API with no artificial delay.
  - Baseline Profile plus Startup Profile, generated by Macrobenchmark in CI.
- **Build.**
  - R8 full mode and resource shrinking.
  - No reflection-based libraries.
  - Per-ABI APK splits.
  - Native library built with the workspace's `lto="fat"`, `panic="abort"`,
    `strip`, and `opt-level=3`. Compare against `opt-level="s"` for size.

### 5.6 Size

- Drop `libv2ray.aar` (Go, about 30 MB per ABI) and hev.
- Ship only Iran-relevant rule data (`geoip:ir`, `geosite:ir`, private,
  ads). Full geosite/geoip download on demand, only if the user enables
  custom routing.
- **Target: under 12 MB per-ABI APK** (arm64). To be verified once the
  first release build exists.

### 5.7 Performance budgets (enforced in CI)

| Metric | Budget | Tool |
|---|---|---|
| Cold start → first frame | < 350 ms (Pixel 6a), < 700 ms (low-end, API 26) | Macrobenchmark `StartupTimingMetric` |
| Home frame time while connecting animation runs | P90 < 8 ms at 120 Hz, 0 janky frames | `FrameTimingMetric` |
| Servers list fling, 2,000 rows | < 1% janky frames | `FrameTimingMetric` |
| Time-to-connected, warm cache | < 2 s median | instrumented test with netem Iran profile |
| Time-to-connected, cold | < 12 s median | same |
| Throughput through TUN, arm64 | ≥ 90% of the same outbound in proxy mode | iperf3 over adb-reverse |
| `:vpn` PSS connected | < 35 MB | `dumpsys meminfo` |
| Idle-connected drain | ≤ 2%/h | batterystats |

A regression beyond 10% on any row fails the build.

---

## 6. UI and UX — a VPN, not a config manager

### 6.1 Principles

- **One decision on the home screen: connect or not.** Everything technical
  is secondary and optional.
- **No v2rayNG patterns anywhere:**
  - no floating action button;
  - no toolbar overflow menu;
  - no list-first home;
  - no raw protocol names in primary UI;
  - no long preference screens;
  - no "test all / sort / export" menus.
- **Words, not jargon.** "Fastest server", "Germany · 140 ms",
  "Anti-censorship: Auto". Protocol, transport and security appear only in a
  server's detail sheet.
- **Persian first.** RTL layouts, Vazirmatn, Persian numerals in Persian
  locale, and every string translated. English secondary.

### 6.2 Structure

Floating glass bottom bar with four destinations:

| Tab | Purpose |
|---|---|
| **Home** | The orb, the current server, live speed |
| **Servers** | Country-grouped list, favourites, own subscriptions |
| **Scanner** | Clean Cloudflare IP scanner |
| **Settings** | Rewritten from scratch, §6.5 |

### 6.3 Home: the connect orb

A direct translation of the TUI's `connect_orb.rs` into Compose, keeping the
same visual language:

- **Three concentric rings** at scales 1.0 / 0.80 / 0.62, with a centred label
  and the ZeroNet mark.
- **Idle.** Dim rings. Press: the orb scales to 0.96 on a spring and a haptic
  (`CONTEXT_CLICK`) fires.
- **Connecting.**
  - A bright 90° arc sweeps the outer ring (amber accent).
  - The orb's shape slowly morphs circle ↔ 12-sided "cookie" using
    `androidx.graphics.shapes`.
  - A stage line under it counts up live: "Checking 214 servers… 3 working".
- **Connected.**
  - The rings turn green and **breathe**: colour interpolated every frame,
    as in the TUI's `pulse_phase`.
  - A one-shot ripple and a `CONFIRM` haptic.
  - A soft radial glow behind the orb fades in.
- **Error.** A broken red ring with a one-line reason and a "Try again" chip.
- **Below the orb:**
  - a server card (flag, country, "Fastest", ping; tap opens the server sheet);
  - a compact live ↓/↑ speed readout with a 60-second sparkline;
  - session time.
- **Background.** A slow, low-contrast gradient field that takes its hue from
  the state (neutral → amber → green). It is drawn once per frame on a single
  layer and paused when not visible.

**Palette.** The TUI's **Golden Dark** is the brand default: bg `#0D0F12`,
surface `#161920`, accent `#F59E0B`, ok `#10B981`, err `#EF4444`. Material
You dynamic colour is an option (on by default on Android 12+, with the orb
keeping semantic green/red). Light, dark, system and AMOLED black are
supported. The TUI's other palettes (Nightshade, Arctic, Sakura, Paper,
Contrast) are offered as themes, so the phone and terminal apps feel like one
product.

### 6.4 Motion system

| Moment | Motion |
|---|---|
| Tab switch | Shared-axis horizontal with spring (`MotionScheme.standard`). The bottom-bar indicator is a liquid pill that stretches toward the target, then settles. |
| Server row → detail | Shared element: row container → bottom sheet, flag flies |
| Connect / connected | `MotionScheme.expressive` springs, shape morph, ripple |
| Back | Predictive back on every route (Android 14+) |
| Lists | `animateItem()` placement. Pings count up as they stream in. |
| Sheets | Spring-driven drag with velocity hand-off, iOS-like rubber-banding at the edges |

Reduced motion (system "remove animations" or animator scale 0) turns springs
into 150 ms fades and stops ambient animation.

### 6.5 Settings — rewritten from scratch

No preference-screen lists. Settings is **a single scrollable page of grouped
cards**:
- a search field at the top;
- each card is a *topic* with plain-language controls;
- the current value is visible without opening anything;
- advanced detail lives in bottom sheets, not nested screens.

| Card | Controls (primary) | Behind "More" (sheet) |
|---|---|---|
| **Connection** | Mode: *VPN* / *Proxy only* (segmented). Auto-connect: *Off / On app start / On untrusted Wi-Fi*. Auto-switch to faster server (toggle). | Kill switch (deep-links to Android always-on + lockdown, with explanation), IPv6, MTU |
| **Servers & sources** | Sources: count and "Manage". Preferred countries (chips). Refresh: *Auto / Manual*. | Per-source toggles, add own subscription or link, protocol preferences, hide/show insecure |
| **Split tunnelling** | Iranian sites & apps go direct (toggle, on). Apps: *All through VPN / Only selected / All except selected*, with app picker. | LAN bypass, custom domain/IP rules |
| **Share over Wi-Fi** | One toggle. When on, shows a card with `IP:port`, QR, PAC link, device count. | Port, username/password, HTTP vs SOCKS |
| **Anti-censorship** | Level: *Off / Auto / Strong* (maps to Zray evasion presets: fragmentation, noise, SNI desync). Clean IPs: *Use scanner results* (toggle). | Fragment size/interval, padding, noise, DNS mode (FakeDNS, DoH server) |
| **Appearance** | Theme (visual swatches of the palettes), dark/light/system/AMOLED, dynamic colour, language, motion *Full / Reduced*. | — |
| **Data & privacy** | Data used this month. Logs: *Off* by default. | Export logs, backup/restore, clear history |
| **About** | Version, Zray-Core version, licences, source code link | — |

Every change applies immediately, with no "Save". Changes that need a
reconnect (mode, MTU) show an inline "Applies on next connect · Reconnect now"
chip instead of a dialog.

### 6.6 Servers tab

- **Top segmented control:** *Recommended · Countries · Mine*.
  - *Recommended*: the current alive set with live pings.
  - *Countries*: expandable groups with the best ping per country.
  - *Mine*: the user's own subscriptions and links.
- Search with instant filtering.
- Rows show flag, city/country, ping bar, a favourite star and a small
  CDN/Direct badge.
- A tap connects. A long-press or chevron opens the detail sheet (protocol,
  transport, source, history graph, share QR).

### 6.7 Scanner tab

- A big progress ring echoing the orb.
- Live counters: scanned / responsive / best RTT.
- ISP-aware presets (MCI, Irancell, TCI, Rightel).
- The results list has "Use best 10" and applies automatically to CDN-class
  configs.
- Runs in `:vpn` through `zero-scanner`. Pauses when the app is backgrounded
  unless the user pins it with a notification.

---

## 7. Zray-Core work required (phase 2)

1. **JNI layer in `zray-mobile`** (`jni` crate), exporting
   `com.zeronet.mobile.core.ZrayNative`.
   - The protect callback is held as a `GlobalRef` to the `VpnService`, with
     the `JavaVM` cached.
   - Results cross JNI as compact JSON or `ByteArray` batches, never one
     call per item.
2. **New entry points:**
   - `zray_reload(json)` (wraps `Server::reload`);
   - `zray_measure_delay(json, url, timeout)`;
   - `zray_discover(sources_json, network_id, callback)` with cancellation;
   - `zray_scan(...)` with progress callback;
   - `zray_network_changed()`;
   - `zray_stats_json` extended with per-tag counters (the
     `traffic_counters()` data already exists).
3. **Runtime tuning:** configurable worker threads (default `min(cores,3)`),
   TUN read batching, buffer pooling.
4. **Parser gaps** from §3.6.
5. **Move `subscription.rs`, `sharelink.rs` and `ping.rs` from
   `zeronet-tui`** into a shared crate (`zero-discovery`), so the TUI and the
   app share one engine.
6. **CI:** add `armv7-linux-androideabi` and `x86_64-linux-android` builds
   next to the existing `aarch64` job.

---

## 8. Phases

Each phase ends with something installable and verified on a device or
emulator.

| # | Phase | Done when |
|---|---|---|
| 0 | Repo bootstrap | ✅ `6cfc14b` |
| 1 | Import v2rayNG 2.2.6. Rename to `com.zeronet.mobile`, strip branding. Add an `upstream` remote. | Debug APK builds and connects on the Go core |
| 2 | Zray bridge + §7. `ZrayNative`, cargo-ndk Gradle task, remove libv2ray/hev. | TUN and proxy work on Zray. Feed-eval parse-rate gain confirmed. |
| 3 | Discovery engine (§4), `sources.json`, Room store, `tools/feed-eval` | Fresh install → connected in Iran, cold < 12 s median |
| 4 | Design system: palettes, typography/RTL, orb, motion tokens, glass | Component gallery verified light/dark, fa/en, API 24/31/37 |
| 5 | Screens: Home, Servers, Scanner, Settings (§6), onboarding | Every kept feature reachable, no dead controls |
| 6 | Sharing over Wi-Fi, split tunnelling, QS tile, always-on | A laptop browses through the phone |
| 7 | Performance pass: §5.7 budgets, baseline profiles, macrobenchmarks, battery | All budgets met in CI |
| 8 | Independent review, device matrix QA, release pipeline (signed ABI splits via GitHub Actions) | Tagged release builds reproducibly |

---

## 9. Local toolchain still needed

Android SDK (platform 37), NDK r28+, `adb`, `cargo-ndk`, and the Rust targets
`armv7-linux-androideabi` and `x86_64-linux-android` (`aarch64` is already
installed). JDK 25 is present.
