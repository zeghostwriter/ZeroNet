# ZeroNet

A censorship-resistant networking stack for restrictive networks, built in Rust,
with a terminal client and an Android app.

This repository consolidates three parts:

| Path | What it is |
|---|---|
| `crates/` | **zray-core** — the Rust workspace: protocol, transport, DNS, routing, evasion, discovery, TUN, and the mobile FFI (`zray-mobile`). |
| `crates/zeronet-tui/` | **zeronet-tui** — the terminal user interface built on the core. |
| `ZeroNet-Mobile/` | **ZeroNet-Mobile** — the Android app (Kotlin/Compose) that loads the core as a native library. |

## Building

### Core + TUI

```sh
cargo build --release
cargo run -p zeronet-tui
```

### Android app

The app loads native libraries produced from the Rust core. Build them, then
assemble the app:

```sh
ANDROID_HOME=$HOME/Android/Sdk bash crates/zray-mobile/build-android.sh \
  ZeroNet-Mobile/app/src/main/jniLibs
cd ZeroNet-Mobile && ./gradlew assembleDebug
```

## Layout

- `crates/zero-*` — the individual core crates (see each crate's docs).
- `crates/zray-cli`, `crates/zray-mobile` — CLI and mobile FFI front-ends.
- `fuzz/` — fuzz targets for the parsers.
- `deploy/` — the optional Cloudflare Worker edge (credentials are set as
  Wrangler secrets, never committed).
- `docs/` — design and contract notes, including the native FFI contract.

## License

See `LICENSE` (MPL-2.0 for the core). Third-party notices for the Android app
live under `ZeroNet-Mobile/app/src/main/assets/licenses/`.
