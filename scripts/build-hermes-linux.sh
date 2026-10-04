#!/usr/bin/env bash

# Build the pinned, unmodified Hermes source for Linux and install the static
# artifact closure consumed by crates/ibex2/build.rs.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
source "$script_dir/hermes-version.sh"

hermes_commit="${HERMES_VERSION:-$IBEX_HERMES_VANILLA_BUILD_REF}"
debugger="${HERMES_ENABLE_DEBUGGER:-true}"
clean=false

usage() {
  printf '%s\n' \
    'usage: scripts/build-hermes-linux.sh [--vanilla] [--debug|--release] [--clean] [commit]'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vanilla|--intl) shift ;;
    --no-intl) echo 'Ibex 2 Linux Hermes requires Intl' >&2; exit 2 ;;
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
cache_dir="$cache_root/$hermes_commit-$variant"
source_dir="$cache_root/upstream"
artifacts="$cache_dir/artifacts"
engine_dir="$repo_root/linux/Frameworks-vanilla"
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

for command_name in cmake git node pkg-config; do
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
    --build-flag=-DCMAKE_BUILD_TYPE=Release
    --build-flag=-DHERMES_ENABLE_DEBUGGER="$debugger"
    --build-flag=-DHERMES_ENABLE_INTL=true
    --build-flag=-DHERMES_BUILD_APPLE_FRAMEWORK=false
    --build-flag=-DHERMES_BUILD_SHARED_JSI=false
    --build-flag=-DCMAKE_POSITION_INDEPENDENT_CODE=ON
    --link-directive=rustc-link-search=native=linux-static
    --link-directive=rustc-link-lib=static=hermesvm_a
    --link-directive=rustc-link-lib=static=jsi
    --link-directive=rustc-link-lib=static=boost_context
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
    "$artifacts/bin/hermesc" \
    "$artifacts/bin/hermes"; do
    [[ -e "$required" ]] || return 1
  done
  mkdir -p "$engine_dir" "$tools_dir"
  rm -rf "$engine_dir/hermes-headers" "$engine_dir/linux-static"
  cp -R "$artifacts/hermes-headers" "$engine_dir/hermes-headers"
  cp -R "$artifacts/linux-static" "$engine_dir/linux-static"
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
git -C "$source_dir" fetch origin "$hermes_commit"
resolved="$(git -C "$source_dir" rev-parse --verify "${hermes_commit}^{commit}")"
[[ "$resolved" == "$hermes_commit" ]] \
  || { echo "Hermes commit resolved to the wrong object: $resolved" >&2; exit 1; }
git -C "$source_dir" checkout --detach "$resolved"
git -C "$source_dir" reset --hard "$resolved"
git -C "$source_dir" clean -ffdx

rm -rf "$cache_dir"
mkdir -p "$cache_dir"
build_dir="$cache_dir/build"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
(( jobs <= 32 )) || jobs=32
generator=(-G 'Unix Makefiles')
command -v ninja >/dev/null 2>&1 && generator=(-G Ninja)

cmake -S "$source_dir" -B "$build_dir" "${generator[@]}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DHERMES_ENABLE_DEBUGGER="$debugger" \
  -DHERMES_ENABLE_INTL=true \
  -DHERMES_BUILD_APPLE_FRAMEWORK=false \
  -DHERMES_BUILD_SHARED_JSI=false \
  -DHERMES_ENABLE_TEST_SUITE=false \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build "$build_dir" --target hermesvm hermesvm_a hermesc hermes -j "$jobs"

mkdir -p "$artifacts/linux-static" "$artifacts/hermes-headers/hermes" \
  "$artifacts/hermes-headers/jsi" "$artifacts/bin"
cp "$build_dir/lib/libhermesvm_a.a" "$artifacts/linux-static/"
cp "$build_dir/jsi/libjsi.a" "$artifacts/linux-static/"
boost_archive="$(find "$build_dir/external/boost" -type f -name libboost_context.a -print -quit)"
[[ -n "$boost_archive" ]] || { echo "Boost.Context archive not found" >&2; exit 1; }
cp "$boost_archive" "$artifacts/linux-static/libboost_context.a"

icu_lib_dir="$(pkg-config --variable=libdir icu-i18n)"
tinfo_lib_dir="$(pkg-config --variable=libdir tinfo)"
for archive in libicui18n.a libicuuc.a libicudata.a; do
  [[ -f "$icu_lib_dir/$archive" ]] \
    || { echo "static ICU archive is missing: $icu_lib_dir/$archive" >&2; exit 1; }
  cp "$icu_lib_dir/$archive" "$artifacts/linux-static/"
done
[[ -f "$tinfo_lib_dir/libtinfo.a" ]] \
  || { echo "static terminfo archive is missing: $tinfo_lib_dir/libtinfo.a" >&2; exit 1; }
cp "$tinfo_lib_dir/libtinfo.a" "$artifacts/linux-static/"

cp -R "$source_dir/API/jsi/jsi/." "$artifacts/hermes-headers/jsi/"
cp -R "$source_dir/API/hermes/." "$artifacts/hermes-headers/hermes/"
cp -R "$source_dir/public/hermes/Public" "$artifacts/hermes-headers/hermes/"
cp "$build_dir/bin/hermesc" "$artifacts/bin/hermesc"
cp "$build_dir/bin/hermes" "$artifacts/bin/hermes"

install_artifacts
