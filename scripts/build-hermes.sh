#!/usr/bin/env bash

# Build the pinned, unmodified Hermes source for Apple platforms and install
# the artifact layout consumed by crates/ibex2/build.rs.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
source "$script_dir/hermes-version.sh"

hermes_commit="${HERMES_VERSION:-$IBEX_HERMES_VANILLA_BUILD_REF}"
debugger="${HERMES_ENABLE_DEBUGGER:-true}"
clean=false

usage() {
  printf '%s\n' \
    'usage: scripts/build-hermes.sh [--vanilla] [--debug|--release] [--clean] [commit]'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vanilla) shift ;;
    --debug) debugger=true; shift ;;
    --release|--no-debugger) debugger=false; shift ;;
    --clean) clean=true; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) hermes_commit="$1"; shift ;;
  esac
done
[[ "$hermes_commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "vanilla Hermes requires an exact 40-hex commit: $hermes_commit" >&2; exit 2; }

case "$debugger" in
  1|true|TRUE|yes|YES|on|ON) debugger=true; variant=debug ;;
  *) debugger=false; variant=release ;;
esac

host_machine="$(uname -m)"
case "$host_machine" in
  arm64|aarch64) host_arch=arm64; tool_arch=arm64; receipt_target=aarch64-apple-darwin ;;
  x86_64|amd64) host_arch=x86_64; tool_arch=x64; receipt_target=x86_64-apple-darwin ;;
  *) echo "unsupported Apple build host: $host_machine" >&2; exit 2 ;;
esac

cache_root="${IBEX_HERMES_CACHE_DIR:-$HOME/.cache/ibex/hermes-apple-vanilla}"
cache_dir="$cache_root/$hermes_commit-$variant"
source_dir="$cache_root/upstream"
artifacts="$cache_dir/artifacts"
frameworks_dir="$repo_root/ios/Frameworks-vanilla"
if [[ "$debugger" == false ]]; then
  frameworks_dir="$repo_root/ios/Frameworks-vanilla-nodebug"
fi
tools_dir="$repo_root/tools/hermes-vanilla"

ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$clean" == true ]]; then
  rm -rf "$cache_dir"
  echo "cleaned $cache_dir"
  exit 0
fi

for command_name in cmake git xcodebuild lipo libtool node; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "$command_name is required" >&2; exit 1; }
done

normalize_archive() {
  local archive="$1" temp_dir arch
  local -a slices=()
  temp_dir="$(mktemp -d "$(dirname "$archive")/.normalize.XXXXXX")"
  for arch in $(lipo -archs "$archive" | tr ' ' '\n' | LC_ALL=C sort); do
    lipo "$archive" -thin "$arch" -output "$temp_dir/$arch.in.a"
    libtool -static -D -no_warning_for_no_symbols \
      -o "$temp_dir/$arch.a" "$temp_dir/$arch.in.a"
    slices+=("$temp_dir/$arch.a")
  done
  lipo -create "${slices[@]}" -output "$temp_dir/result.a"
  chmod 0644 "$temp_dir/result.a"
  mv "$temp_dir/result.a" "$archive"
  rm -rf "$temp_dir"
}

write_receipt() {
  local -a receipt_args=(
    "$script_dir/hermes-input-receipt.mjs"
    "$frameworks_dir"
    --target "$receipt_target"
    --profile "$variant"
    --commit "$hermes_commit"
    --compiler "$tools_dir/hermesc-macos-$tool_arch"
    --build-flag=-DHERMES_APPLE_TARGET_PLATFORM=macosx
    --build-flag=-DCMAKE_OSX_ARCHITECTURES=x86_64\;arm64
    --build-flag=-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0
    --build-flag=-DHERMES_ENABLE_DEBUGGER="$debugger"
    --build-flag=-DHERMES_ENABLE_INTL=true
    --build-flag=-DHERMES_BUILD_APPLE_FRAMEWORK=true
    --build-flag=-DCMAKE_BUILD_TYPE=MinSizeRel
    --link-directive=rustc-link-search=native=macos-static
    --link-directive=rustc-link-lib=static=hermesvm_a
    --link-directive=rustc-link-lib=static=jsi
    --link-directive=rustc-link-lib=static=boost_context
    --link-directive=rustc-link-lib=c++
    --link-directive=rustc-link-lib=framework=CoreFoundation
    --link-directive=rustc-link-lib=framework=Foundation
  )
  node "${receipt_args[@]}"
}

install_artifacts() {
  local required
  for required in \
    "$artifacts/hermesvm.xcframework" \
    "$artifacts/hermesvm.framework" \
    "$artifacts/macos-static/libhermesvm_a.a" \
    "$artifacts/hermes-headers" \
    "$artifacts/bin/hermesc"; do
    [[ -e "$required" ]] || return 1
  done
  mkdir -p "$frameworks_dir" "$tools_dir"
  rm -rf "$frameworks_dir/hermes.xcframework" \
    "$frameworks_dir/hermesvm.framework" \
    "$frameworks_dir/macos-static" \
    "$frameworks_dir/hermes-headers"
  cp -R "$artifacts/hermesvm.xcframework" "$frameworks_dir/hermes.xcframework"
  cp -R "$artifacts/hermesvm.framework" "$frameworks_dir/hermesvm.framework"
  cp -R "$artifacts/macos-static" "$frameworks_dir/macos-static"
  cp -R "$artifacts/hermes-headers" "$frameworks_dir/hermes-headers"
  cp "$artifacts/bin/hermesc" "$tools_dir/hermesc-macos-$tool_arch"
  if [[ -f "$artifacts/bin/hermes" ]]; then
    cp "$artifacts/bin/hermes" "$tools_dir/hermes"
  fi
  write_receipt
  echo "installed vanilla Hermes $hermes_commit in $frameworks_dir"
}

if install_artifacts; then
  exit 0
fi

if [[ ! -d "$source_dir/.git" ]]; then
  mkdir -p "$cache_root"
  git clone https://github.com/facebook/hermes.git "$source_dir"
fi
git -C "$source_dir" reset --hard HEAD
git -C "$source_dir" clean -ffdx
git -C "$source_dir" fetch origin "$hermes_commit"
resolved="$(git -C "$source_dir" rev-parse --verify "${hermes_commit}^{commit}")"
[[ "$resolved" == "$hermes_commit" ]] \
  || { echo "Hermes commit resolved to the wrong object: $resolved" >&2; exit 1; }
git -C "$source_dir" checkout --detach "$resolved"
git -C "$source_dir" reset --hard "$resolved"
git -C "$source_dir" clean -ffdx

rm -rf "$cache_dir"
mkdir -p "$cache_dir"
host_build="$cache_dir/build-host"
ios_build="$cache_dir/build-ios"
sim_build="$cache_dir/build-ios-simulator"
mac_build="$cache_dir/build-macos"
stage="$cache_dir/stage"
jobs="$(sysctl -n hw.ncpu)"

cmake -S "$source_dir" -B "$host_build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_SYSROOT=macosx \
  -DCMAKE_OSX_ARCHITECTURES="$host_arch" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
  -DHERMES_ENABLE_TEST_SUITE=false \
  -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
  -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
cmake --build "$host_build" --target hermesc hermes -j "$jobs"

configure_apple() {
  local build_dir="$1" platform="$2" arches="$3" deployment="$4"
  cmake -S "$source_dir" -B "$build_dir" \
    -DHERMES_APPLE_TARGET_PLATFORM="$platform" \
    -DCMAKE_OSX_ARCHITECTURES="$arches" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$deployment" \
    -DHERMES_ENABLE_DEBUGGER="$debugger" \
    -DHERMES_ENABLE_INTL=true \
    -DHERMES_ENABLE_LIBFUZZER=false \
    -DHERMES_ENABLE_FUZZILLI=false \
    -DHERMES_ENABLE_TEST_SUITE=false \
    -DHERMES_ENABLE_BITCODE=false \
    -DHERMES_BUILD_APPLE_FRAMEWORK=true \
    -DHERMES_BUILD_SHARED_JSI=false \
    -DIMPORT_HOST_COMPILERS="$host_build/ImportHostCompilers.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_C_FLAGS='-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability' \
    -DCMAKE_CXX_FLAGS='-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability'
  cmake --build "$build_dir" --target ExtensionsBytecodeInclude -j 1
  cmake --build "$build_dir" --target hermesvm -j "$jobs"
}

configure_apple "$ios_build" iphoneos arm64 15.0
configure_apple "$sim_build" iphonesimulator 'x86_64;arm64' 15.0
configure_apple "$mac_build" macosx 'x86_64;arm64' 12.0
cmake --build "$mac_build" --target hermesvmlean_a -j "$jobs"

mkdir -p "$stage"
xcodebuild -create-xcframework \
  -framework "$ios_build/lib/hermesvm.framework" \
  -framework "$sim_build/lib/hermesvm.framework" \
  -framework "$mac_build/lib/hermesvm.framework" \
  -output "$stage/hermesvm.xcframework"

mkdir -p "$artifacts/macos-static" "$artifacts/hermes-headers/hermes" \
  "$artifacts/hermes-headers/jsi" "$artifacts/bin"
cp -R "$stage/hermesvm.xcframework" "$artifacts/hermesvm.xcframework"
cp -R "$mac_build/lib/hermesvm.framework" "$artifacts/hermesvm.framework"
cp "$mac_build/lib/libhermesvm_a.a" "$artifacts/macos-static/"
cp "$mac_build/lib/libhermesvmlean_a.a" "$artifacts/macos-static/"
cp "$mac_build/jsi/libjsi.a" "$artifacts/macos-static/"
boost_archive="$(find "$mac_build/external/boost" -type f -name libboost_context.a -print -quit)"
[[ -n "$boost_archive" ]] || { echo "Boost.Context archive not found" >&2; exit 1; }
cp "$boost_archive" "$artifacts/macos-static/libboost_context.a"
for archive in "$artifacts/macos-static/"*.a; do normalize_archive "$archive"; done
cp -R "$source_dir/API/jsi/jsi/." "$artifacts/hermes-headers/jsi/"
cp -R "$source_dir/API/hermes/." "$artifacts/hermes-headers/hermes/"
cp -R "$source_dir/public/hermes/Public" "$artifacts/hermes-headers/hermes/"
cp "$host_build/bin/hermesc" "$artifacts/bin/hermesc"
[[ ! -f "$host_build/bin/hermes" ]] || cp "$host_build/bin/hermes" "$artifacts/bin/hermes"

install_artifacts
