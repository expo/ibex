#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${ANDROID_TARGET:-aarch64-linux-android}"
ANDROID_API="${ANDROID_API:-24}"

find_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi
  if [[ -n "${ANDROID_NDK_ROOT:-}" && -d "$ANDROID_NDK_ROOT" ]]; then
    echo "$ANDROID_NDK_ROOT"
    return
  fi

  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [[ -n "$sdk" && -d "$sdk/ndk" ]]; then
    find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort -r | head -n 1
    return
  fi

  local default_sdk="$HOME/Library/Android/sdk"
  if [[ -d "$default_sdk/ndk" ]]; then
    find "$default_sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort -r | head -n 1
    return
  fi
}

ndk="$(find_ndk || true)"
if [[ -z "$ndk" ]]; then
  echo "Android NDK not found. Set ANDROID_NDK_HOME or install an NDK under ANDROID_HOME/ndk." >&2
  exit 1
fi

prebuilt_root="$ndk/toolchains/llvm/prebuilt"
toolchain="$(find "$prebuilt_root" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"
if [[ -z "$toolchain" || ! -d "$toolchain/bin" ]]; then
  echo "Android LLVM toolchain not found under $prebuilt_root." >&2
  exit 1
fi

case "$TARGET" in
  aarch64-linux-android)
    clang_prefix="aarch64-linux-android$ANDROID_API"
    ;;
  armv7-linux-androideabi)
    clang_prefix="armv7a-linux-androideabi$ANDROID_API"
    ;;
  i686-linux-android)
    clang_prefix="i686-linux-android$ANDROID_API"
    ;;
  x86_64-linux-android)
    clang_prefix="x86_64-linux-android$ANDROID_API"
    ;;
  *)
    echo "Unsupported Android target: $TARGET" >&2
    exit 1
    ;;
esac

if [[ ! -x "$toolchain/bin/$clang_prefix-clang" ]]; then
  echo "Android compiler not found: $toolchain/bin/$clang_prefix-clang" >&2
  exit 1
fi

target_env="${TARGET//-/_}"
target_env_upper="$(printf '%s' "$target_env" | tr '[:lower:]' '[:upper:]')"

export ANDROID_NDK_HOME="$ndk"
export EXACT_ALLOW_FALLBACK="${EXACT_ALLOW_FALLBACK:-1}"
export PATH="$toolchain/bin:$PATH"
export "CC_$target_env=$toolchain/bin/$clang_prefix-clang"
export "CXX_$target_env=$toolchain/bin/$clang_prefix-clang++"
export "AR_$target_env=$toolchain/bin/llvm-ar"
export "RANLIB_$target_env=$toolchain/bin/llvm-ranlib"
export "CARGO_TARGET_${target_env_upper}_LINKER=$toolchain/bin/$clang_prefix-clang"

if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$TARGET"; then
  rustup target add "$TARGET"
fi

if [[ ! -d "$ROOT/android/hermes-android" || ! -d "$ROOT/android/react-android" ]]; then
  "$ROOT/scripts/install-android-hermes.sh"
fi

if [[ $# -eq 0 ]]; then
  set -- build --target "$TARGET" --features openssl-crypto
fi

exec cargo "$@"
