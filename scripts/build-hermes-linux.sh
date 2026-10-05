#!/usr/bin/env bash

# Build the pinned, unmodified Hermes source for Linux and install the static
# artifact closure consumed by crates/ibex2/build.rs.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
source "$script_dir/hermes-version.sh"
source "$script_dir/icu-version.sh"

hermes_commit="${HERMES_VERSION:-$IBEX_HERMES_VANILLA_BUILD_REF}"
debugger="${HERMES_ENABLE_DEBUGGER:-true}"
clean=false

usage() {
  printf '%s\n' \
    'usage: scripts/build-hermes-linux.sh [--vanilla] [--debug|--release] [--clean] [commit]'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vanilla|--no-intl) shift ;;
    --intl) echo 'Linux engine Intl is disabled; enable ibex2/intl instead' >&2; exit 2 ;;
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

machine="$(uname -m)"
case "$machine" in
  x86_64|amd64) tool_arch=x64; receipt_target=x86_64-unknown-linux-gnu ;;
  arm64|aarch64) tool_arch=arm64; receipt_target=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported Linux build host: $machine" >&2; exit 2 ;;
esac

cache_root="${IBEX_HERMES_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ibex/hermes-linux-vanilla}"
# The cache key names the non-lite engine, exact ICU source, and exact trimmed
# filter so no older Unicode-lite or distro-ICU artifact can satisfy it.
cache_dir="$cache_root/${hermes_commit}-${variant}-no-intl-nonlite-icu-${IBEX_ICU_SOURCE_COMMIT:0:12}-${IBEX_ICU_TRIMMED_FILTER_SHA256:0:12}"
source_dir="$cache_root/upstream"
icu_source_dir="$cache_root/icu-upstream"
artifacts="$cache_dir/artifacts"
icu_trimmed_build="$cache_dir/build-icu-trimmed"
icu_trimmed_install="$cache_dir/install-icu-trimmed"
icu_full_build="$cache_dir/build-icu-full"
icu_full_install="$cache_dir/install-icu-full"
engine_dir="$repo_root/linux/Frameworks-vanilla"
tools_dir="$repo_root/tools/hermes-vanilla"
icu_filter="$repo_root/scripts/icu74-filter-root-en.json"

ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$clean" == true ]]; then
  rm -rf "$cache_dir"
  echo "cleaned $cache_dir"
  exit 0
fi

for command_name in cmake git make ninja nm node pkg-config python3; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "$command_name is required" >&2; exit 1; }
done

write_receipt() {
  local -a receipt_args=(
    "$script_dir/hermes-input-receipt.mjs"
    "$engine_dir"
    --target "$receipt_target"
    --profile "$variant"
    --commit "$hermes_commit"
    --compiler "$tools_dir/hermesc-linux-$tool_arch"
    --engine-archive linux-static/libhermesvm_a.a
    --lean-engine-archive linux-static/libhermesvmlean_a.a
    --build-flag=-DCMAKE_BUILD_TYPE=Release
    --build-flag=-DHERMES_ENABLE_DEBUGGER="$debugger"
    --build-flag=-DHERMES_ENABLE_INTL=false
    --build-flag=-DHERMES_UNICODE_LITE=false
    --build-flag=-DHERMES_USE_STATIC_ICU=true
    --build-flag=-DHERMES_BUILD_APPLE_FRAMEWORK=false
    --build-flag=-DHERMES_BUILD_SHARED_JSI=false
    --build-flag=-DCMAKE_POSITION_INDEPENDENT_CODE=ON
    --link-directive=rustc-link-search=native=linux-static
    --link-directive=rustc-link-lib=static=hermesvm_a
    --link-directive=rustc-link-lib=static=jsi
    --link-directive=rustc-link-lib=static=boost_context
    --icu-trimmed-data-archive=linux-static/libicudata.a
    --icu-full-data-archive=linux-static/libicudata-full.a
    --icu-trimmed-filter=share/icu/filters-root-en.json
    --link-directive=rustc-link-lib=static=icui18n
    --link-directive=rustc-link-lib=static=icuuc
    --link-directive=rustc-link-lib=static=icudata
    --link-directive=rustc-link-lib=static=tinfo
    --link-directive=rustc-link-lib=stdc++
    --link-directive=rustc-link-lib=dl
    --link-directive=rustc-link-lib=pthread
    --link-directive=rustc-link-lib=m
  )
  node "${receipt_args[@]}"
}

install_artifacts() {
  local required
  for required in \
    "$artifacts/hermes-headers" \
    "$artifacts/linux-static/libhermesvm_a.a" \
    "$artifacts/linux-static/libhermesvmlean_a.a" \
    "$artifacts/linux-static/libicudata.a" \
    "$artifacts/linux-static/libicudata-full.a" \
    "$artifacts/share/icu/filters-root-en.json" \
    "$artifacts/LICENSE.icu" \
    "$artifacts/bin/hermesc" \
    "$artifacts/bin/hermes"; do
    [[ -e "$required" ]] || return 1
  done
  mkdir -p "$engine_dir" "$tools_dir"
  rm -rf "$engine_dir/hermes-headers" "$engine_dir/linux-static"
  rm -rf "$engine_dir/share"
  cp -R "$artifacts/hermes-headers" "$engine_dir/hermes-headers"
  cp -R "$artifacts/linux-static" "$engine_dir/linux-static"
  cp -R "$artifacts/share" "$engine_dir/share"
  cp "$artifacts/LICENSE.icu" "$engine_dir/LICENSE.icu"
  cp "$artifacts/bin/hermesc" "$tools_dir/hermesc-linux-$tool_arch"
  cp "$artifacts/bin/hermes" "$tools_dir/hermes-linux-$tool_arch"
  write_receipt
  echo "installed vanilla Hermes $hermes_commit in $engine_dir"
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

rm -rf "$cache_dir"
mkdir -p "$cache_dir"

ibex_verify_icu_trimmed_filter "$icu_filter"
ibex_checkout_icu_source "$icu_source_dir"
(
  cd "$icu_source_dir/icu4c/source"
  PYTHONPATH=python python3 -m icutools.databuilder \
    --mode=gnumake --src_dir=data --filter_file="$icu_filter" >/dev/null
)
ibex_build_icu_linux \
  "$icu_source_dir" "$icu_trimmed_build" "$icu_trimmed_install" "$icu_filter"
ibex_build_icu_linux \
  "$icu_source_dir" "$icu_full_build" "$icu_full_install"
ibex_verify_icu_data_variants \
  "$icu_trimmed_install/lib/libicudata.a" \
  "$icu_full_install/lib/libicudata.a"
git -C "$source_dir" fetch origin "$hermes_commit"
resolved="$(git -C "$source_dir" rev-parse --verify "${hermes_commit}^{commit}")"
[[ "$resolved" == "$hermes_commit" ]] \
  || { echo "Hermes commit resolved to the wrong object: $resolved" >&2; exit 1; }
git -C "$source_dir" checkout --detach "$resolved"
git -C "$source_dir" reset --hard "$resolved"
git -C "$source_dir" clean -ffdx

build_dir="$cache_dir/build"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
(( jobs <= 4 )) || jobs=4
generator=(-G Ninja)

cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DHERMES_ENABLE_DEBUGGER="$debugger" \
  -DHERMES_ENABLE_INTL=false \
  -DHERMES_UNICODE_LITE=false \
  -DHERMES_USE_STATIC_ICU=true \
  -DCMAKE_PREFIX_PATH="$icu_trimmed_install" \
  -DICU_ROOT="$icu_trimmed_install" \
  -DHERMES_BUILD_APPLE_FRAMEWORK=false \
  -DHERMES_BUILD_SHARED_JSI=false \
  -DHERMES_ENABLE_TEST_SUITE=false \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_JOB_POOLS=link_pool=2 \
  -DCMAKE_JOB_POOL_LINK=link_pool
cmake --build "$build_dir" \
  --target hermesvm hermesvm_a hermesvmlean_a hermesc hermes -j "$jobs"

mkdir -p "$artifacts/linux-static" "$artifacts/hermes-headers/hermes" \
  "$artifacts/hermes-headers/jsi" "$artifacts/bin"
cp "$build_dir/lib/libhermesvm_a.a" "$artifacts/linux-static/"
cp "$build_dir/lib/libhermesvmlean_a.a" "$artifacts/linux-static/"
cp "$build_dir/jsi/libjsi.a" "$artifacts/linux-static/"
boost_archive="$(find "$build_dir/external/boost" -type f -name libboost_context.a -print -quit)"
[[ -n "$boost_archive" ]] || { echo "Boost.Context archive not found" >&2; exit 1; }
cp "$boost_archive" "$artifacts/linux-static/libboost_context.a"

tinfo_lib_dir="$(pkg-config --variable=libdir tinfo)"
for archive in libicui18n.a libicuuc.a libicudata.a; do
  [[ -f "$icu_trimmed_install/lib/$archive" ]] \
    || { echo "static ICU archive is missing: $icu_trimmed_install/lib/$archive" >&2; exit 1; }
  cp "$icu_trimmed_install/lib/$archive" "$artifacts/linux-static/"
done
[[ -f "$icu_full_install/lib/libicudata.a" ]] \
  || { echo "full ICU data archive is missing: $icu_full_install/lib/libicudata.a" >&2; exit 1; }
cp "$icu_full_install/lib/libicudata.a" "$artifacts/linux-static/libicudata-full.a"
[[ -d "$icu_trimmed_install/include/unicode" ]] \
  || { echo "ICU headers are missing: $icu_trimmed_install/include/unicode" >&2; exit 1; }
cp -R "$icu_trimmed_install/include/unicode" "$artifacts/hermes-headers/"
mkdir -p "$artifacts/share/icu"
cp "$icu_filter" "$artifacts/share/icu/filters-root-en.json"
cp "$icu_source_dir/LICENSE" "$artifacts/LICENSE.icu"
[[ -f "$tinfo_lib_dir/libtinfo.a" ]] \
  || { echo "static terminfo archive is missing: $tinfo_lib_dir/libtinfo.a" >&2; exit 1; }
cp "$tinfo_lib_dir/libtinfo.a" "$artifacts/linux-static/"

cp -R "$source_dir/API/jsi/jsi/." "$artifacts/hermes-headers/jsi/"
cp -R "$source_dir/API/hermes/." "$artifacts/hermes-headers/hermes/"
cp -R "$source_dir/public/hermes/Public" "$artifacts/hermes-headers/hermes/"
cp "$build_dir/bin/hermesc" "$artifacts/bin/hermesc"
cp "$build_dir/bin/hermes" "$artifacts/bin/hermes"

install_artifacts
