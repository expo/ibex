#!/usr/bin/env bash

# Build and deterministically package one Apple or Linux full-VM Hermes release
# bundle. The Windows builder has a PowerShell counterpart.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
source "$script_dir/hermes-version.sh"

usage() {
  printf '%s\n' \
    'usage: scripts/build-hermes-vanilla-release.sh <target> <archive.tar.gz>' \
    '' \
    'targets:' \
    '  aarch64-apple-darwin' \
    '  x86_64-apple-darwin' \
    '  aarch64-apple-ios' \
    '  universal-apple-ios-simulator' \
    '  x86_64-unknown-linux-gnu' \
    '  aarch64-unknown-linux-gnu'
}

[[ $# -eq 2 ]] || { usage >&2; exit 2; }
target="$1"
output_archive="$2"
commit="$IBEX_HERMES_VANILLA_SOURCE_COMMIT"
host_os="$(uname -s)"
host_machine="$(uname -m)"

case "$host_machine" in
  arm64|aarch64) host_arch=arm64 ;;
  x86_64|amd64) host_arch=x86_64 ;;
  *) echo "unsupported build host architecture: $host_machine" >&2; exit 2 ;;
esac

platform=""
target_arches=""
deployment_target=""
profile="release"
case "$target" in
  aarch64-apple-darwin)
    [[ "$host_os" == Darwin && "$host_arch" == arm64 ]] \
      || { echo "$target requires an arm64 macOS host" >&2; exit 2; }
    platform=macosx; target_arches=arm64; deployment_target=12.0; profile=min-size-release ;;
  x86_64-apple-darwin)
    [[ "$host_os" == Darwin && "$host_arch" == x86_64 ]] \
      || { echo "$target requires an x86_64 macOS host" >&2; exit 2; }
    platform=macosx; target_arches=x86_64; deployment_target=12.0; profile=min-size-release ;;
  aarch64-apple-ios)
    [[ "$host_os" == Darwin ]] || { echo "$target requires a macOS host" >&2; exit 2; }
    platform=iphoneos; target_arches=arm64; deployment_target=15.0; profile=min-size-release ;;
  universal-apple-ios-simulator)
    [[ "$host_os" == Darwin ]] || { echo "$target requires a macOS host" >&2; exit 2; }
    platform=iphonesimulator; target_arches='arm64;x86_64'; deployment_target=15.0; profile=min-size-release ;;
  x86_64-unknown-linux-gnu)
    [[ "$host_os" == Linux && "$host_arch" == x86_64 ]] \
      || { echo "$target requires an x86_64 Linux host" >&2; exit 2; } ;;
  aarch64-unknown-linux-gnu)
    [[ "$host_os" == Linux && "$host_arch" == arm64 ]] \
      || { echo "$target requires an arm64 Linux host" >&2; exit 2; } ;;
  *) usage >&2; exit 2 ;;
esac

for command_name in cmake git node python3; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "$command_name is required" >&2; exit 1; }
done
if [[ "$host_os" == Darwin ]]; then
  for command_name in lipo libtool xcodebuild; do
    command -v "$command_name" >/dev/null 2>&1 \
      || { echo "$command_name is required" >&2; exit 1; }
  done
else
  command -v pkg-config >/dev/null 2>&1 || { echo "pkg-config is required" >&2; exit 1; }
fi

cache_root="${IBEX_HERMES_RELEASE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ibex/hermes-vanilla-release}"
cache_dir="$cache_root/$commit/$target"
source_dir="$cache_root/upstream"
build_dir="$cache_dir/build"
host_build="$cache_dir/build-host"
bundle_dir="$cache_dir/bundle"

ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ! -d "$source_dir/.git" ]]; then
  mkdir -p "$cache_root"
  mkdir -p "$source_dir"
  git -C "$source_dir" init
  git -C "$source_dir" remote add origin https://github.com/facebook/hermes.git
fi
git -C "$source_dir" fetch --depth=1 --no-tags origin "$commit"
resolved="$(git -C "$source_dir" rev-parse --verify "${commit}^{commit}")"
[[ "$resolved" == "$commit" ]] \
  || { echo "Hermes commit resolved to the wrong object: $resolved" >&2; exit 1; }
git -C "$source_dir" reset --hard "$commit"
git -C "$source_dir" clean -ffdx

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
(( jobs <= 16 )) || jobs=16
generator=(-G 'Unix Makefiles')
command -v ninja >/dev/null 2>&1 && generator=(-G Ninja)

build_flags=(
  -DHERMES_ENABLE_DEBUGGER=false
  -DHERMES_ENABLE_INTL=true
  -DHERMES_BUILD_SHARED_JSI=false
  -DHERMES_ENABLE_TEST_SUITE=false
)

if [[ "$host_os" == Darwin ]]; then
  cmake -S "$source_dir" -B "$host_build" "${generator[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT=macosx \
    -DCMAKE_OSX_ARCHITECTURES="$host_arch" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
    -DHERMES_ENABLE_TEST_SUITE=false \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
  cmake --build "$host_build" --target hermesc -j "$jobs"
  build_flags+=(
    -DCMAKE_BUILD_TYPE=MinSizeRel
    "-DHERMES_APPLE_TARGET_PLATFORM=$platform"
    "-DCMAKE_OSX_ARCHITECTURES=$target_arches"
    "-DCMAKE_OSX_DEPLOYMENT_TARGET=$deployment_target"
    -DHERMES_BUILD_APPLE_FRAMEWORK=false
    -DHERMES_ENABLE_LIBFUZZER=false
    -DHERMES_ENABLE_FUZZILLI=false
    -DHERMES_ENABLE_BITCODE=false
  )
  cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" \
    "${build_flags[@]}" \
    -DIMPORT_HOST_COMPILERS="$host_build/ImportHostCompilers.cmake" \
    -DCMAKE_C_FLAGS='-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability' \
    -DCMAKE_CXX_FLAGS='-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability'
  cmake --build "$build_dir" --target ExtensionsBytecodeInclude -j 1
  cmake --build "$build_dir" --target hermesvm_a jsi boost_context -j "$jobs"
  compiler="$host_build/bin/hermesc"
else
  build_flags+=(
    -DCMAKE_BUILD_TYPE=Release
    -DHERMES_BUILD_APPLE_FRAMEWORK=false
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  )
  cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" "${build_flags[@]}"
  cmake --build "$build_dir" --target hermesvm_a jsi boost_context hermesc -j "$jobs"
  compiler="$build_dir/bin/hermesc"
fi

[[ -f "$build_dir/lib/libhermesvm_a.a" ]] \
  || { echo "full Hermes VM archive was not built" >&2; exit 1; }
[[ -f "$build_dir/jsi/libjsi.a" ]] || { echo "JSI archive was not built" >&2; exit 1; }
boost_archive="$(find "$build_dir/external/boost" -type f -name libboost_context.a -print -quit)"
[[ -n "$boost_archive" ]] || { echo "Boost.Context archive was not built" >&2; exit 1; }
[[ -x "$compiler" ]] || { echo "hermesc was not built at $compiler" >&2; exit 1; }

# cache_dir is commit- and target-qualified above; bundle_dir cannot name a
# checkout, home directory, or caller-supplied broad path.
rm -rf "$bundle_dir"
mkdir -p "$bundle_dir/bin" "$bundle_dir/include/hermes" "$bundle_dir/include/jsi" "$bundle_dir/lib"
cp "$build_dir/lib/libhermesvm_a.a" "$bundle_dir/lib/"
cp "$build_dir/jsi/libjsi.a" "$bundle_dir/lib/"
cp "$boost_archive" "$bundle_dir/lib/libboost_context.a"
cp "$compiler" "$bundle_dir/bin/hermesc"
cp -R "$source_dir/API/jsi/jsi/." "$bundle_dir/include/jsi/"
cp -R "$source_dir/API/hermes/." "$bundle_dir/include/hermes/"
cp -R "$source_dir/public/hermes/Public" "$bundle_dir/include/hermes/"
cp "$source_dir/LICENSE" "$bundle_dir/LICENSE.hermes"

if [[ "$host_os" == Darwin ]]; then
  normalize_archive() {
    local archive="$1" temp_dir arch
    local -a arches=()
    local -a slices=()
    temp_dir="$(mktemp -d "$(dirname "$archive")/.normalize.XXXXXX")"
    while IFS= read -r arch; do arches+=("$arch"); done \
      < <(lipo -archs "$archive" | tr ' ' '\n' | LC_ALL=C sort)
    if [[ ${#arches[@]} -eq 1 ]]; then
      libtool -static -D -no_warning_for_no_symbols \
        -o "$temp_dir/result.a" "$archive"
    else
      for arch in "${arches[@]}"; do
        lipo "$archive" -thin "$arch" -output "$temp_dir/$arch.in.a"
        libtool -static -D -no_warning_for_no_symbols \
          -o "$temp_dir/$arch.a" "$temp_dir/$arch.in.a"
        slices+=("$temp_dir/$arch.a")
      done
      lipo -create "${slices[@]}" -output "$temp_dir/result.a"
    fi
    chmod 0644 "$temp_dir/result.a"
    mv "$temp_dir/result.a" "$archive"
    rm -rf "$temp_dir"
  }
  for archive in "$bundle_dir/lib/"*.a; do normalize_archive "$archive"; done
else
  icu_lib_dir="$(pkg-config --variable=libdir icu-i18n)"
  tinfo_lib_dir="$(pkg-config --variable=libdir tinfo)"
  for archive in libicui18n.a libicuuc.a libicudata.a; do
    [[ -f "$icu_lib_dir/$archive" ]] \
      || { echo "static ICU archive is missing: $icu_lib_dir/$archive" >&2; exit 1; }
    cp "$icu_lib_dir/$archive" "$bundle_dir/lib/"
  done
  [[ -f "$tinfo_lib_dir/libtinfo.a" ]] \
    || { echo "static terminfo archive is missing: $tinfo_lib_dir/libtinfo.a" >&2; exit 1; }
  cp "$tinfo_lib_dir/libtinfo.a" "$bundle_dir/lib/"
fi

receipt_args=(
  "$bundle_dir"
  --target "$target"
  --profile "$profile"
  --engine-archive lib/libhermesvm_a.a
)
for flag in "${build_flags[@]}"; do receipt_args+=(--build-flag="$flag"); done
receipt_args+=(
  --link-directive=rustc-link-search=native=lib
  --link-directive=rustc-link-lib=static=hermesvm_a
  --link-directive=rustc-link-lib=static=jsi
  --link-directive=rustc-link-lib=static=boost_context
)
if [[ "$host_os" == Darwin ]]; then
  receipt_args+=(
    --link-directive=rustc-link-lib=c++
    --link-directive=rustc-link-lib=framework=CoreFoundation
    --link-directive=rustc-link-lib=framework=Foundation
  )
else
  receipt_args+=(
    --link-directive=rustc-link-lib=static=icui18n
    --link-directive=rustc-link-lib=static=icuuc
    --link-directive=rustc-link-lib=static=icudata
    --link-directive=rustc-link-lib=static=tinfo
    --link-directive=rustc-link-lib=stdc++
    --link-directive=rustc-link-lib=dl
    --link-directive=rustc-link-lib=pthread
    --link-directive=rustc-link-lib=m
  )
fi
node "$script_dir/hermes-input-receipt.mjs" "${receipt_args[@]}"
python3 "$script_dir/package-hermes-vanilla-release.py" "$bundle_dir" "$output_archive"

printf 'built %s from %s\n' "$output_archive" "$commit"
