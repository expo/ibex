#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/ibex-macho-proof.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT

xcrun --sdk macosx clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"$repo_root/src/engine" \
  "$repo_root/src/engine/macho_mapping_proof.cc" \
  "$repo_root/tests/native_macho_mapping_proof.cc" \
  -o "$test_dir/native_macho_mapping_proof"

real_fixtures=()
simulator_fat="$repo_root/ios/Frameworks/hermes.xcframework/ios-arm64_x86_64-simulator/hermesvm.framework/hermesvm"
device_thin="$repo_root/ios/Frameworks/hermes.xcframework/ios-arm64/hermesvm.framework/hermesvm"
if [ -f "$simulator_fat" ]; then
  simulator_arm64="$test_dir/hermesvm-ios-simulator-arm64"
  simulator_x86_64="$test_dir/hermesvm-ios-simulator-x86_64"
  xcrun lipo "$simulator_fat" -thin arm64 -output "$simulator_arm64"
  xcrun lipo "$simulator_fat" -thin x86_64 -output "$simulator_x86_64"
  real_fixtures+=(
    "$simulator_fat" "$simulator_arm64"
    "$simulator_fat" "$simulator_x86_64"
  )
fi
if [ -f "$device_thin" ]; then
  real_fixtures+=("$device_thin" "$device_thin")
fi

"$test_dir/native_macho_mapping_proof" "${real_fixtures[@]}"
