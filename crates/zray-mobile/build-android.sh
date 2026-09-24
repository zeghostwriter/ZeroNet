#!/usr/bin/env bash
# Build libzray_mobile.so (with the JNI surface) for every Android ABI the app
# ships and copy each into <out_jniLibs_dir>/<abi>/.
#
#   crates/zray-mobile/build-android.sh app/src/main/jniLibs
#
# Environment:
#   ANDROID_NDK_HOME  NDK to use (default: newest under $ANDROID_HOME/ndk, then
#                     ~/Android/Sdk/ndk)
#   ZRAY_ABIS         space-separated ABIs (default: "arm64-v8a armeabi-v7a x86_64")
#   ZRAY_API          minimum API level (default: 30)
#   ZRAY_PROFILE      cargo profile (default: release-mobile — release with
#                     unwinding panics, so the JNI guards can catch them)
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <out_jniLibs_dir>" >&2
    exit 2
fi
out="$1"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
abis="${ZRAY_ABIS:-arm64-v8a armeabi-v7a x86_64}"
api="${ZRAY_API:-30}"
profile="${ZRAY_PROFILE:-release-mobile}"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    sdk="${ANDROID_HOME:-$HOME/Android/Sdk}"
    ANDROID_NDK_HOME="$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -z "$ANDROID_NDK_HOME" ]]; then
        echo "error: no NDK found; set ANDROID_NDK_HOME" >&2
        exit 1
    fi
fi
export ANDROID_NDK_HOME
command -v cargo-ndk >/dev/null || { echo "error: cargo-ndk is not installed (cargo install cargo-ndk)" >&2; exit 1; }

targets=()
for abi in $abis; do targets+=(-t "$abi"); done

echo "NDK:     $ANDROID_NDK_HOME"
echo "ABIs:    $abis (API $api)"
echo "profile: $profile"
cargo ndk --manifest-path "$root/Cargo.toml" "${targets[@]}" -P "$api" \
    build -p zray-mobile --features jni --profile "$profile"

target_dir="$(cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
for abi in $abis; do
    case "$abi" in
        arm64-v8a) triple=aarch64-linux-android ;;
        armeabi-v7a) triple=armv7-linux-androideabi ;;
        x86_64) triple=x86_64-linux-android ;;
        x86) triple=i686-linux-android ;;
        *) echo "error: unknown ABI $abi" >&2; exit 1 ;;
    esac
    library="$target_dir/$triple/$profile/libzray_mobile.so"
    mkdir -p "$out/$abi"
    cp "$library" "$out/$abi/libzray_mobile.so"
    printf '%-12s %s (%s bytes)\n' "$abi" "$out/$abi/libzray_mobile.so" "$(stat -c %s "$library")"
done
