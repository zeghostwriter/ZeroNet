<div align="center">

<img src="packaging/icons/zeronet.png" alt="ZeroNet" width="170">

# ZeroNet

### Performance, Speed, and Freedom in your hands.
### کارایی، سرعت و آزادی در دستان شما.

<a href="https://github.com/zeghostwriter/ZeroNet/releases/latest"><b>⬇️ دانلود آخرین نسخه</b></a><br>
<a href="https://github.com/zeghostwriter/ZeroNet/releases/latest"><b>⬇️ Download the latest release</b></a>

[فارسی](#فارسی) · [English](#english)

</div>

---

<div dir="rtl">

## فارسی

**زیرونت** یک VPN ساده و سریع برای عبور از فیلترینگ است. برای ویندوز، لینوکس، مک و اندروید. قلب آن **Zray** است، یک هسته‌ی شبکه که از صفر با زبان **Rust** نوشته شده. کانفیگ‌هایی که امروز با Xray کار می‌کنند (VLESS،&rlm; REALITY،&rlm; Vision،&rlm; XHTTP،&rlm; VMess،&rlm; Trojan،&rlm; Shadowsocks و…) در زیرونت هم کار می‌کنند.

### ⚡ چرا این‌قدر سریع است؟

زبان Rust به کد ماشین کامپایل می‌شود و Garbage Collector ندارد. پس برنامه هیچ‌وقت برای «جمع‌کردن حافظه» مکث نمی‌کند و فقط همان حافظه‌ای را می‌گیرد که واقعاً لازم دارد. نتیجه: اینترنت سریع‌تر، مصرف کمتر رم و CPU، و باتری ماندگارتر، حتی روی سیستم‌ها و گوشی‌های ضعیف.

ما Zray و Xray-core را روی یک سیستم، با یک سرور و یک کانفیگ مقایسه کردیم. تنها چیزی که عوض شد هسته‌ی کلاینت بود:

| | Xray-core | **Zray (زیرونت)** |
|---|---:|---:|
| سرعت دانلود با TLS (یک اتصال) | ۳۴۹ مگابایت بر ثانیه | **۵۳۲ مگابایت بر ثانیه** (۵۳٪ سریع‌تر) |
| مصرف CPU برای هر گیگابایت (TLS) | ۳٫۰ ثانیه | **۱٫۶ ثانیه** (۴۶٪ کمتر) |
| رم در حالت بیکار | ۲۹ مگابایت | **۸ مگابایت** (۳٫۷ برابر کمتر) |
| بیشترین مصرف رم زیر بار | ۵۱ مگابایت | **۲۱ مگابایت** (۲٫۴ برابر کمتر) |

</div>

<p align="center">
  <img src="docs/benchmarks/throughput-tls.png" alt="Throughput, VLESS + TLS" width="49%">
  <img src="docs/benchmarks/memory.png" alt="Memory usage" width="49%">
  <img src="docs/benchmarks/cpu-tls.png" alt="CPU per GB, VLESS + TLS" width="49%">
  <img src="docs/benchmarks/throughput-plain.png" alt="Throughput, plain VLESS" width="49%">
</p>

<div dir="rtl">

در همه‌ی تست‌ها، Zray مصرف CPU کمتری داشت. تنها موردی که Xray جلو بود، دانلود تک‌اتصالی بدون TLS بود (۸۷۳ در برابر ۷۹۹ مگابایت بر ثانیه). همه‌ی نتایج را همان‌طور که اندازه گرفته شد گذاشته‌ایم. روش تست و ابزار تکرار آن در [docs/benchmarks](docs/benchmarks) است.

### 📥 نصب (فقط چند کلیک)

همه‌ی فایل‌ها در صفحه‌ی **[Releases](https://github.com/zeghostwriter/ZeroNet/releases/latest)** هستند:

| سیستم | فایل | چه کار کنم؟ |
|---|---|---|
| 🪟 ویندوز | `ZeroNet-Windows-x64.zip` | فایل را از حالت فشرده خارج کنید و روی `ZeroNet.exe` دوبار کلیک کنید. اگر ویندوز هشدار داد: **More info ←&rlm; Run anyway**. |
| 🐧 لینوکس | `ZeroNet-Linux-x86_64.AppImage` | راست‌کلیک ← Properties ← تیک **Allow executing file as program**. بعد دوبار کلیک کنید. برنامه خودش در ترمینال باز می‌شود. |
| 🍎 مک | `ZeroNet-macOS-universal.zip` | از حالت فشرده خارج کنید، `ZeroNet.app` را به Applications ببرید. بار اول **راست‌کلیک ← Open** (برنامه امضای اپل ندارد). |
| 🤖 اندروید | `ZeroNet-Android-universal.apk` | نصب کنید. اگر پرسید، اجازه‌ی نصب از منابع ناشناس را بدهید. |

> برای گوشی‌های جدید فایل `arm64-v8a` کم‌حجم‌تر است. اگر مطمئن نیستید، `universal` را بگیرید.

### 🧭 استفاده

1. لینک کانفیگ (`vless://`،&rlm; `vmess://`،&rlm; `trojan://`،&rlm; `ss://` یا لینک ساب‌اسکریپشن) را کپی کنید و در زیرونت **Ctrl+V** بزنید.
2. روی دکمه‌ی اتصال کلیک کنید. همه‌چیز با موس کار می‌کند، مثل یک برنامه‌ی معمولی.
3. در تنظیمات، **System Proxy** را روی **SET SYSTEM** بگذارید (یا آن‌قدر **Ctrl+P** بزنید تا SET SYSTEM شود) تا بقیه‌ی برنامه‌ها هم از آن استفاده کنند.

**سه حالت اتصال** (روی صفحه‌ی اصلی اپ اندروید):
- **معمولی:** فقط سرورهای رمزگذاری‌شده (TLS یا REALITY) که مثل HTTPS معمولی دیده می‌شوند، همراه چند سرور پشتیبان. بهترین انتخاب برای استفاده‌ی روزمره.
- **سریع:** به اولین سروری که کار کند وصل می‌شود، بدون جست‌وجوی اضافه. سریع‌ترین راه برای وصل شدن.
- **گیمینگ:** کمترین پینگ، UDP روشن (برای بازی‌ها و تماس صوتی)، بدون سرورهای پشت CDN، و سرور وسط بازی عوض نمی‌شود. سایت‌ها و سرورهای بازی ایرانی مستقیم می‌روند.

**برنامه‌های دیگر:**
- **تلگرام:** Settings ←&rlm; Advanced ←&rlm; Connection type ←&rlm; **Use system proxy**. در لینوکس بعد از روشن‌کردن پروکسی، تلگرام را کامل ببندید و دوباره باز کنید.
- **فایرفاکس:** Settings ←&rlm; Network Settings ←&rlm; **Use system proxy settings**.

**حالت TUN** (همه‌ی برنامه‌ها بدون تنظیم جداگانه): در لینوکس و مک زیرونت رمز سیستم را می‌پرسد. در ویندوز برنامه را با **Run as administrator** باز کنید (فایل `wintun.dll` کنار برنامه است).

### 🛠️ ساخت از سورس

</div>

```sh
cargo run --release -p zeronet-tui        # desktop app
cd ZeroNet-Mobile && ./gradlew assembleRelease   # Android (see ZeroNet-Mobile/README.md)
```

---

## English

**ZeroNet** is a fast, simple VPN for getting past censorship, on Windows,
Linux, macOS and Android. Its heart is **Zray**, a networking core written
from scratch in **Rust**. It speaks the same configs as Xray: VLESS, REALITY,
Vision, XHTTP, VMess, Trojan, Shadowsocks and more. A config that works in
Xray works here.

### ⚡ Why it's fast

Rust compiles to native code and has no garbage collector. The core never
pauses to clean up memory and only holds the memory it actually uses. That
means more speed, less RAM and CPU, and longer battery life, even on old
laptops and cheap phones.

We ran Zray and Xray-core on the same machine, against the same server,
from the same config file. Only the client core changed:

| | Xray-core | **Zray (ZeroNet)** |
|---|---:|---:|
| Download over TLS, 1 connection | 349 MB/s | **532 MB/s** (+53%) |
| CPU time per GB over TLS | 3.0 s | **1.6 s** (−46%) |
| Memory at idle | 29 MB | **8 MB** (3.7× less) |
| Peak memory under load | 51 MB | **21 MB** (2.4× less) |

Zray used less CPU per gigabyte in every test. Xray was faster in one case:
a single plain-TCP download (873 vs 799 MB/s). We publish every number as
measured. The charts are above; the method and the harness to reproduce them
are in [docs/benchmarks](docs/benchmarks).

### 📥 Install

Everything is on the **[Releases page](https://github.com/zeghostwriter/ZeroNet/releases/latest)**:

| Platform | File | What to do |
|---|---|---|
| 🪟 Windows | `ZeroNet-Windows-x64.zip` | Extract it and double-click `ZeroNet.exe`. If SmartScreen appears: **More info → Run anyway**. |
| 🐧 Linux | `ZeroNet-Linux-x86_64.AppImage` | Right-click → Properties → **Allow executing file as program**, then double-click. It opens in a terminal window on its own. (`aarch64` builds and a plain `.tar.gz` are there too.) |
| 🍎 macOS | `ZeroNet-macOS-universal.zip` | Unzip and move `ZeroNet.app` to Applications. The first time, **right-click → Open**: the app isn't notarized by Apple. If macOS says it is damaged, run `xattr -dr com.apple.quarantine /Applications/ZeroNet.app`. |
| 🤖 Android | `ZeroNet-Android-universal.apk` | Install it and allow installs from this source if asked. `arm64-v8a` is a smaller download for most modern phones. |

ZeroNet is a terminal app that works like a desktop app: mouse, hover,
menus, clicks. When you double-click it, it opens its own terminal window.
On macOS it runs in Terminal.app, so double-clicking always works.

### 🧭 Using it

1. Copy a config link (`vless://`, `vmess://`, `trojan://`, `ss://`, or a
   subscription URL) and press **Ctrl+V** in ZeroNet.
2. Click connect.
3. In Settings, set **System Proxy** to **SET SYSTEM** (or press **Ctrl+P**
   until it shows SET SYSTEM) so other apps use it too.

**Three connection modes** (on the Android home screen):
- **Normal:** encrypted servers only (TLS or REALITY, which look like ordinary HTTPS), with backups ready. The everyday choice.
- **Fast:** connects to the first server that works, nothing more. The quickest way to get online.
- **Gaming:** lowest ping, UDP allowed (games and voice need it), no CDN-fronted servers, and the server is never switched mid-match. Iranian sites and game servers still go direct.

**Other apps:**
- **Telegram:** Settings → Advanced → Connection type → **Use system proxy**.
  On Linux, Telegram reads the proxy only when it starts, so fully quit it
  and open it again after turning the proxy on.
- **Firefox:** Settings → Network Settings → **Use system proxy settings**.
- **TUN mode** covers every app without configuring anything. On Linux and
  macOS, ZeroNet asks for your password. On Windows, start it with **Run as
  administrator**; the `wintun.dll` it needs ships in the zip.

### 🛠️ Build from source

```sh
cargo run --release -p zeronet-tui              # desktop app
cd ZeroNet-Mobile && ./gradlew assembleRelease  # Android, see ZeroNet-Mobile/README.md
```

Maintainers: pushing a tag like `v0.2.0` builds every download and publishes
the release (`.github/workflows/release.yml`).

### Repository layout

| Path | What it is |
|---|---|
| `crates/` | **Zray-core**, the Rust workspace: protocols, transports, DNS, routing, evasion, discovery, TUN, and the mobile FFI (`zray-mobile`). |
| `crates/zeronet-tui/` | The ZeroNet desktop app. |
| `ZeroNet-Mobile/` | The Android app (Kotlin/Compose), which loads the core as a native library. |
| `packaging/` | Icons and desktop metadata used by the release builds. |
| `docs/` | Benchmarks, protocol specs, and design notes. |
| `deploy/` | The optional Cloudflare Worker edge. |
| `fuzz/` | Fuzz targets for the parsers. |

### License

MPL-2.0 for the core (see `LICENSE`). The Android app is GPL-3.0-or-later
(`ZeroNet-Mobile/LICENSE`); its third-party notices are under
`ZeroNet-Mobile/app/src/main/assets/licenses/`.
