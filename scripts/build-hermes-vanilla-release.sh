#!/usr/bin/env bash

# Build and deterministically package one Apple or Linux Hermes release bundle
# containing both the full and lean VM archives. The Windows builder has a
# PowerShell counterpart.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
source "$script_dir/hermes-version.sh"
source "$script_dir/icu-version.sh"

usage() {
  printf '%s\n' \
    'usage: scripts/build-hermes-vanilla-release.sh <target> <archive.tar.gz>' \
    '' \
    'targets:' \
    '  aarch64-apple-darwin' \
    '  x86_64-apple-darwin' \
    '  aarch64-apple-ios' \
    '  universal-apple-ios-simulator' \
    '  aarch64-apple-tvos' \
    '  aarch64-apple-tvos-simulator' \
    '  x86_64-unknown-linux-gnu' \
    '  aarch64-unknown-linux-gnu' \
    '  aarch64-linux-android      (ANDROID_NDK_HOME, or the SDK'"'"'s newest NDK)'
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
  aarch64-apple-tvos)
    [[ "$host_os" == Darwin ]] || { echo "$target requires a macOS host" >&2; exit 2; }
    platform=appletvos; target_arches=arm64; deployment_target=15.0; profile=min-size-release ;;
  aarch64-apple-tvos-simulator)
    [[ "$host_os" == Darwin ]] || { echo "$target requires a macOS host" >&2; exit 2; }
    platform=appletvsimulator; target_arches=arm64; deployment_target=15.0; profile=min-size-release ;;
  x86_64-unknown-linux-gnu)
    [[ "$host_os" == Linux && "$host_arch" == x86_64 ]] \
      || { echo "$target requires an x86_64 Linux host" >&2; exit 2; } ;;
  aarch64-unknown-linux-gnu)
    [[ "$host_os" == Linux && "$host_arch" == arm64 ]] \
      || { echo "$target requires an arm64 Linux host" >&2; exit 2; } ;;
  aarch64-linux-android)
    # Cross-built with the NDK from a macOS or Linux host. Hermes's own
    # HERMES_IS_ANDROID build needs fbjni and a JVM for Unicode and Intl; a
    # native embedder has neither, so this bundle takes Unicode from a static
    # ICU (as the Linux bundles do) and has no Intl.
    android_ndk="${ANDROID_NDK_HOME:-}"
    if [[ -z "$android_ndk" ]]; then
      sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
      android_ndk="$(ls -d "$sdk"/ndk/* 2>/dev/null | LC_ALL=C sort -V | tail -1)"
    fi
    [[ -f "$android_ndk/build/cmake/android.toolchain.cmake" ]] \
      || { echo "$target needs an Android NDK (set ANDROID_NDK_HOME)" >&2; exit 2; }
    android_api="${IBEX_ANDROID_API:-30}"
    profile=min-size-release ;;
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
  for command_name in make ninja nm pkg-config; do
    command -v "$command_name" >/dev/null 2>&1 \
      || { echo "$command_name is required" >&2; exit 1; }
  done
fi

cache_root="${IBEX_HERMES_RELEASE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ibex/hermes-vanilla-release}"
cache_dir="$cache_root/$commit/$target"
source_dir="$cache_root/upstream"
icu_source_dir="$cache_root/icu-upstream"
build_dir="$cache_dir/build"
host_build="$cache_dir/build-host"
bundle_dir="$cache_dir/bundle"
icu_trimmed_build="$cache_dir/build-icu-trimmed"
icu_trimmed_install="$cache_dir/install-icu-trimmed"
icu_en_build="$cache_dir/build-icu-en"
icu_en_install="$cache_dir/install-icu-en"
icu_full_build="$cache_dir/build-icu-full"
icu_full_install="$cache_dir/install-icu-full"

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
(( jobs <= 4 )) || jobs=4
generator=(-G 'Unix Makefiles')
command -v ninja >/dev/null 2>&1 && generator=(-G Ninja)
if [[ "$host_os" == Linux ]]; then
  generator=(-G Ninja)
fi

build_flags=(
  -DHERMES_ENABLE_DEBUGGER=false
  -DHERMES_BUILD_SHARED_JSI=false
  -DHERMES_ENABLE_TEST_SUITE=false
)

if [[ "$target" == aarch64-linux-android ]]; then
  # The host compiler first, as the Apple branch does; the target build
  # imports it rather than building a hermesc it cannot run.
  host_osx=()
  [[ "$host_os" == Darwin ]] && host_osx=(-DCMAKE_OSX_SYSROOT=macosx \
    -DCMAKE_OSX_ARCHITECTURES="$host_arch" -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0)
  cmake -S "$source_dir" -B "$host_build" "${generator[@]}" \
    -DCMAKE_BUILD_TYPE=Release "${host_osx[@]}" \
    -DHERMES_ENABLE_TEST_SUITE=false \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
  cmake --build "$host_build" --target hermesc -j "$jobs"
  # Unicode through ICU, as the Linux bundles have it (case mapping,
  # normalization, collation, dates; still no Intl): the trimmed root-en data,
  # cross-built with the NDK over a host build that supplies ICU's data tools.
  # Hermes's Android default is its JNI Unicode backend, so the ICU one is
  # selected by its macro (HERMES_PLATFORM_UNICODE_ICU = 3).
  icu_filter="$repo_root/scripts/icu74-filter-root-en.json"
  ibex_verify_icu_trimmed_filter "$icu_filter"
  ibex_checkout_icu_source "$icu_source_dir"
  (
    cd "$icu_source_dir/icu4c/source"
    PYTHONPATH=python python3 -m icutools.databuilder \
      --mode=gnumake --src_dir=data --filter_file="$icu_filter" >/dev/null
  )
  ndk_bin="$(ls -d "$android_ndk"/toolchains/llvm/prebuilt/*/bin | head -1)"
  icu_host_build="$cache_dir/build-icu-host"
  rm -rf "$icu_host_build" "$icu_trimmed_build" "$icu_trimmed_install"
  mkdir -p "$icu_host_build" "$icu_trimmed_build"
  (
    cd "$icu_host_build"
    export ICU_DATA_FILTER_FILE="$icu_filter"
    if [[ "$host_os" == Darwin ]]; then icu_host=MacOSX; else icu_host=Linux; fi
    "$icu_source_dir/icu4c/source/runConfigureICU" "$icu_host" \
      --enable-static --disable-shared --disable-tests --disable-samples --disable-extras
    make -j "$jobs"
  )
  (
    cd "$icu_trimmed_build"
    export ICU_DATA_FILTER_FILE="$icu_filter"
    env CC="$ndk_bin/aarch64-linux-android${android_api}-clang" \
      CXX="$ndk_bin/aarch64-linux-android${android_api}-clang++" \
      AR="$ndk_bin/llvm-ar" RANLIB="$ndk_bin/llvm-ranlib" \
      CFLAGS='-Os -fPIC -ffunction-sections -fdata-sections' \
      CXXFLAGS='-Os -fPIC -ffunction-sections -fdata-sections' \
      "$icu_source_dir/icu4c/source/configure" \
        --host=aarch64-linux-android --with-cross-build="$icu_host_build" \
        --prefix="$icu_trimmed_install" \
        --enable-static --disable-shared --with-data-packaging=static \
        --disable-tests --disable-samples --disable-extras --disable-tools
    make -j "$jobs"
    make install
  )
  for archive in libicui18n.a libicuuc.a libicudata.a; do
    [[ -f "$icu_trimmed_install/lib/$archive" ]] \
      || { echo "Android ICU archive is missing: $icu_trimmed_install/lib/$archive" >&2; exit 1; }
  done
  # hermes.cpp includes <fbjni/fbjni.h> under __ANDROID__ for a JVM thread
  # scope; a native embedder has no JVM, so a no-op stand-in (recorded by digest).
  fbjni_shim="$script_dir/android-fbjni-shim"
  fbjni_shim_digest="$(ibex_sha256 "$fbjni_shim/fbjni/fbjni.h" | awk '{ print $1 }')"
  build_flags+=(
    "-DIBEX_ANDROID_FBJNI_SHIM_SHA256=$fbjni_shim_digest"
    -DHERMES_ENABLE_INTL=false
    -DHERMES_UNICODE_LITE=false
    -DHERMES_USE_STATIC_ICU=true
    -DHERMES_IS_ANDROID=false
    -DCMAKE_BUILD_TYPE=MinSizeRel
    -DANDROID_ABI=arm64-v8a
    "-DANDROID_PLATFORM=android-$android_api"
    -DANDROID_STL=c++_static
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DHERMES_BUILD_APPLE_FRAMEWORK=false
    -DHERMES_ENABLE_LIBFUZZER=false
    -DHERMES_ENABLE_FUZZILLI=false
  )
  cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" \
    "${build_flags[@]}" \
    -DCMAKE_TOOLCHAIN_FILE="$android_ndk/build/cmake/android.toolchain.cmake" \
    -DCMAKE_CXX_FLAGS="-isystem $fbjni_shim -DHERMES_PLATFORM_UNICODE=3" \
    -DCMAKE_PREFIX_PATH="$icu_trimmed_install" \
    -DICU_ROOT="$icu_trimmed_install" \
    -DCMAKE_FIND_ROOT_PATH="$icu_trimmed_install" \
    -DIMPORT_HOST_COMPILERS="$host_build/ImportHostCompilers.cmake"
  cmake --build "$build_dir" --target ExtensionsBytecodeInclude -j 1
  cmake --build "$build_dir" --target hermesvm_a hermesvmlean_a jsi boost_context -j "$jobs"
  compiler="$host_build/bin/hermesc"
elif [[ "$host_os" == Darwin ]]; then
  build_flags+=(
    -DHERMES_ENABLE_INTL=true
  )
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
  cmake --build "$build_dir" --target hermesvm_a hermesvmlean_a jsi boost_context -j "$jobs"
  compiler="$host_build/bin/hermesc"
else
  icu_filter="$repo_root/scripts/icu74-filter-root-en.json"
  icu_en_filter="$repo_root/scripts/icu74-filter-en-intl.json"
  ibex_verify_icu_trimmed_filter "$icu_filter"
  ibex_verify_icu_en_filter "$icu_en_filter"
  ibex_checkout_icu_source "$icu_source_dir"
  for filter in "$icu_filter" "$icu_en_filter"; do
    (
      cd "$icu_source_dir/icu4c/source"
      PYTHONPATH=python python3 -m icutools.databuilder \
        --mode=gnumake --src_dir=data --filter_file="$filter" >/dev/null
    )
  done
  ibex_build_icu_linux \
    "$icu_source_dir" "$icu_trimmed_build" "$icu_trimmed_install" "$icu_filter"
  ibex_build_icu_linux \
    "$icu_source_dir" "$icu_en_build" "$icu_en_install" "$icu_en_filter"
  ibex_build_icu_linux \
    "$icu_source_dir" "$icu_full_build" "$icu_full_install"
  ibex_verify_icu_data_variants \
    "$icu_trimmed_install/lib/libicudata.a" \
    "$icu_en_install/lib/libicudata.a" \
    "$icu_full_install/lib/libicudata.a"
  build_flags+=(
    -DHERMES_ENABLE_INTL=false
    -DHERMES_UNICODE_LITE=false
    -DHERMES_USE_STATIC_ICU=true
    -DCMAKE_BUILD_TYPE=Release
    -DHERMES_BUILD_APPLE_FRAMEWORK=false
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  )
  cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" \
    "${build_flags[@]}" \
    -DCMAKE_PREFIX_PATH="$icu_trimmed_install" \
    -DICU_ROOT="$icu_trimmed_install" \
    -DCMAKE_JOB_POOLS=link_pool=2 \
    -DCMAKE_JOB_POOL_LINK=link_pool
  cmake --build "$build_dir" --target hermesvm_a hermesvmlean_a jsi boost_context hermesc -j "$jobs"
  compiler="$build_dir/bin/hermesc"
fi

[[ -f "$build_dir/lib/libhermesvm_a.a" ]] \
  || { echo "full Hermes VM archive was not built" >&2; exit 1; }
[[ -f "$build_dir/lib/libhermesvmlean_a.a" ]] \
  || { echo "lean Hermes VM archive was not built" >&2; exit 1; }
[[ -f "$build_dir/jsi/libjsi.a" ]] || { echo "JSI archive was not built" >&2; exit 1; }
boost_archive="$(find "$build_dir/external/boost" -type f -name libboost_context.a -print -quit)"
[[ -n "$boost_archive" ]] || { echo "Boost.Context archive was not built" >&2; exit 1; }
[[ -x "$compiler" ]] || { echo "hermesc was not built at $compiler" >&2; exit 1; }

# cache_dir is commit- and target-qualified above; bundle_dir cannot name a
# checkout, home directory, or caller-supplied broad path.
rm -rf "$bundle_dir"
mkdir -p "$bundle_dir/bin" "$bundle_dir/include/hermes" "$bundle_dir/include/jsi" "$bundle_dir/lib"
cp "$build_dir/lib/libhermesvm_a.a" "$bundle_dir/lib/"
cp "$build_dir/lib/libhermesvmlean_a.a" "$bundle_dir/lib/"
cp "$build_dir/jsi/libjsi.a" "$bundle_dir/lib/"
cp "$boost_archive" "$bundle_dir/lib/libboost_context.a"
cp "$compiler" "$bundle_dir/bin/hermesc"
cp -R "$source_dir/API/jsi/jsi/." "$bundle_dir/include/jsi/"
cp -R "$source_dir/API/hermes/." "$bundle_dir/include/hermes/"
cp -R "$source_dir/public/hermes/Public" "$bundle_dir/include/hermes/"
cp "$source_dir/LICENSE" "$bundle_dir/LICENSE.hermes"

if [[ "$target" == aarch64-linux-android ]]; then
  for archive in libicui18n.a libicuuc.a libicudata.a; do
    cp "$icu_trimmed_install/lib/$archive" "$bundle_dir/lib/"
  done
  cp -R "$icu_trimmed_install/include/unicode" "$bundle_dir/include/"
  mkdir -p "$bundle_dir/share/icu"
  cp "$icu_filter" "$bundle_dir/share/icu/filters-root-en.json"
  cp "$icu_source_dir/LICENSE" "$bundle_dir/LICENSE.icu"
  # The NDK's llvm-ar already writes deterministic archives (zero uid, gid and
  # mtime). Never extract and repack: Hermes archives hold same-named members
  # (hermesSupport's and LLVHSupport's ErrorHandling.cpp.o), and extraction
  # keeps only one of each.
  chmod 0644 "$bundle_dir/lib/"*.a
elif [[ "$host_os" == Darwin ]]; then
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
  tinfo_lib_dir="$(pkg-config --variable=libdir tinfo)"
  for archive in libicui18n.a libicuuc.a libicudata.a; do
    [[ -f "$icu_trimmed_install/lib/$archive" ]] \
      || { echo "static ICU archive is missing: $icu_trimmed_install/lib/$archive" >&2; exit 1; }
    cp "$icu_trimmed_install/lib/$archive" "$bundle_dir/lib/"
  done
  [[ -f "$icu_full_install/lib/libicudata.a" ]] \
    || { echo "full ICU data archive is missing: $icu_full_install/lib/libicudata.a" >&2; exit 1; }
  [[ -f "$icu_en_install/lib/libicudata.a" ]] \
    || { echo "English-Intl ICU data archive is missing: $icu_en_install/lib/libicudata.a" >&2; exit 1; }
  cp "$icu_en_install/lib/libicudata.a" "$bundle_dir/lib/libicudata-en.a"
  cp "$icu_full_install/lib/libicudata.a" "$bundle_dir/lib/libicudata-full.a"
  [[ -d "$icu_trimmed_install/include/unicode" ]] \
    || { echo "ICU headers are missing: $icu_trimmed_install/include/unicode" >&2; exit 1; }
  cp -R "$icu_trimmed_install/include/unicode" "$bundle_dir/include/"
  mkdir -p "$bundle_dir/share/icu"
  cp "$icu_filter" "$bundle_dir/share/icu/filters-root-en.json"
  cp "$icu_en_filter" "$bundle_dir/share/icu/filters-en-intl.json"
  cp "$icu_source_dir/LICENSE" "$bundle_dir/LICENSE.icu"
  [[ -f "$tinfo_lib_dir/libtinfo.a" ]] \
    || { echo "static terminfo archive is missing: $tinfo_lib_dir/libtinfo.a" >&2; exit 1; }
  cp "$tinfo_lib_dir/libtinfo.a" "$bundle_dir/lib/"
fi

receipt_args=(
  "$bundle_dir"
  --target "$target"
  --profile "$profile"
  --engine-archive lib/libhermesvm_a.a
  --lean-engine-archive lib/libhermesvmlean_a.a
)
for flag in "${build_flags[@]}"; do receipt_args+=(--build-flag="$flag"); done
receipt_args+=(
  --link-directive=rustc-link-search=native=lib
  --link-directive=rustc-link-lib=static=hermesvm_a
  --link-directive=rustc-link-lib=static=jsi
  --link-directive=rustc-link-lib=static=boost_context
)
if [[ "$target" == aarch64-linux-android ]]; then
  receipt_args+=(
    --link-directive=rustc-link-lib=static=icui18n
    --link-directive=rustc-link-lib=static=icuuc
    --link-directive=rustc-link-lib=static=icudata
    --link-directive=rustc-link-lib=c++_static
    --link-directive=rustc-link-lib=c++abi
    --link-directive=rustc-link-lib=log
    --link-directive=rustc-link-lib=dl
    --link-directive=rustc-link-lib=m
  )
elif [[ "$host_os" == Darwin ]]; then
  receipt_args+=(
    --link-directive=rustc-link-lib=c++
    --link-directive=rustc-link-lib=framework=CoreFoundation
    --link-directive=rustc-link-lib=framework=Foundation
  )
else
  receipt_args+=(
    --icu-trimmed-data-archive=lib/libicudata.a
    --icu-en-data-archive=lib/libicudata-en.a
    --icu-full-data-archive=lib/libicudata-full.a
    --icu-trimmed-filter=share/icu/filters-root-en.json
    --icu-en-filter=share/icu/filters-en-intl.json
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
