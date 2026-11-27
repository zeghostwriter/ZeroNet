#!/usr/bin/env bash
# Host JNI smoke test: builds libzray_mobile.so for this machine with the
# `jni` feature, compiles the Java stand-ins for the app's classes, and runs
# them against the library. Proves the exported names and signatures match
# ZeroNet-Mobile/docs/native-contract.md and that callbacks reach Java.
#
#   crates/zray-mobile/tests/jni-host/run.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

cargo build --manifest-path "$root/Cargo.toml" -p zray-mobile --features jni
target_dir="$(cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

javac -d "$out" "$here"/src/com/zeronet/mobile/core/*.java
java -Xcheck:jni -Djava.library.path="$target_dir/debug" -cp "$out" com.zeronet.mobile.core.Main
