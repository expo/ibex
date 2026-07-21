#!/usr/bin/env bash
#
# build-hermes-linux.sh
# Builds Hermes from source for Linux and installs artifacts for Ibex.
#
# Usage:
#   ./scripts/build-hermes-linux.sh
#   ./scripts/build-hermes-linux.sh --clean
#   ./scripts/build-hermes-linux.sh --release
#   ./scripts/build-hermes-linux.sh --debug
#   ./scripts/build-hermes-linux.sh <git-tag-or-branch-or-commit>
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

# Default to the pinned Hermes commit — the stable branch name moves under
# cold clones (ENG-23092).
HERMES_VERSION="${HERMES_VERSION:-$IBEX_HERMES_BUILD_REF}"
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"
HERMES_INTL="${HERMES_ENABLE_INTL:-false}"
CLEAN_CACHE=false
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/exact/hermes-linux"
LINUX_DIR="$PROJECT_ROOT/linux"
LINUX_LIB_DIR="$LINUX_DIR/lib"
LINUX_HEADERS_DIR="$LINUX_DIR/hermes-headers"
TOOLS_DIR="$PROJECT_ROOT/tools/hermes"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            CLEAN_CACHE=true
            shift
            ;;
        --release|--no-debugger)
            HERMES_DEBUGGER=false
            shift
            ;;
        --debug)
            HERMES_DEBUGGER=true
            shift
            ;;
        --intl)
            HERMES_INTL=true
            shift
            ;;
        --no-intl)
            HERMES_INTL=false
            shift
            ;;
        *)
            HERMES_VERSION="$1"
            shift
            ;;
    esac
done

ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$CLEAN_CACHE" == "true" ]]; then
    rm -rf "$CACHE_DIR"
    echo "Cleaned Hermes Linux cache: $CACHE_DIR"
    exit 0
fi

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not found. Install cmake first."
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git not found."
    exit 1
fi

NUM_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
SRC_DIR="$CACHE_DIR/hermes-src"
BUILD_DIR="$CACHE_DIR/build"
INSTALL_DIR="$CACHE_DIR/install"

mkdir -p "$CACHE_DIR"

if [[ ! -d "$SRC_DIR/.git" ]]; then
    rm -rf "$SRC_DIR"
    git clone https://github.com/facebook/hermes.git "$SRC_DIR"
fi

cd "$SRC_DIR"
git reset --hard HEAD
git clean -ffdx
git fetch --all --tags
if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
    # Treat a full object ID as an object identity before consulting branch
    # names; a 40-hex remote ref must never shadow the reviewed commit.
    if ! git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null; then
        git fetch origin "$HERMES_VERSION"
    fi
    git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null \
        || { echo "Requested Hermes commit is unavailable: $HERMES_VERSION" >&2; exit 1; }
    git checkout --detach "${HERMES_VERSION}^{commit}"
elif [[ "$HERMES_VERSION" == "static_h" || "$HERMES_VERSION" == "main" ]]; then
    git checkout --detach origin/static_h
elif git rev-parse --verify --quiet "origin/$HERMES_VERSION" >/dev/null; then
    git checkout --detach "origin/$HERMES_VERSION"
else
    git checkout --detach "$HERMES_VERSION"
fi

CHECKED_OUT_COMMIT="$(git rev-parse HEAD^{commit})"
if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ && "$CHECKED_OUT_COMMIT" != "$HERMES_VERSION" ]]; then
    echo "Checked-out Hermes commit $CHECKED_OUT_COMMIT differs from requested object $HERMES_VERSION" >&2
    exit 1
fi
git reset --hard "$CHECKED_OUT_COMMIT"
git clean -ffdx
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
    echo "Hermes source checkout is not pristine after reset/clean" >&2
    exit 1
fi

# Build/install directories live beside the source checkout on Linux, so erase
# them before patch verification as part of the same locked pristine boundary.
rm -rf "$BUILD_DIR" "$INSTALL_DIR"

# @ref LLP 0013#upstream-tracking — the real index and complete persistent
# checkout are pristine before the carried Hermes patch stack is replayed.
"$SCRIPT_DIR/apply-hermes-patches.sh" "$SRC_DIR"

ACTUAL_COMMIT="$(printf '%s' "$CHECKED_OUT_COMMIT" | cut -c1-12)"
echo "Building Hermes for Linux from commit: $ACTUAL_COMMIT"
echo "Debugger enabled: $HERMES_DEBUGGER"
echo "Intl enabled: $HERMES_INTL"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

GENERATOR=(-G "Unix Makefiles")
if command -v ninja >/dev/null 2>&1; then
    GENERATOR=(-G Ninja)
fi

cmake -S . -B "$BUILD_DIR" "${GENERATOR[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DHERMES_ENABLE_DEBUGGER="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL="$HERMES_INTL" \
    -DHERMES_BUILD_APPLE_FRAMEWORK=OFF \
    -DHERMES_BUILD_SHARED_JSI=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON

cmake --build "$BUILD_DIR" --target hermesvm hermesvm_a hermesc -j"$NUM_CORES"

mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/bin" "$INSTALL_DIR/include"

# The source runtime uses the shared object; LLP 0029 compiled stubs consume
# the full static archive. Publish them together so one authenticated Hermes
# bundle supports both profiles without relabeling either artifact.
if [[ -f "$BUILD_DIR/lib/libhermesvm.so" && -f "$BUILD_DIR/lib/libhermesvm_a.a" ]]; then
    cp "$BUILD_DIR/lib/libhermesvm.so" "$INSTALL_DIR/lib/"
    cp "$BUILD_DIR/lib/libhermesvm_a.a" "$INSTALL_DIR/lib/"
else
    echo "Could not find both libhermesvm.so and libhermesvm_a.a in $BUILD_DIR/lib"
    exit 1
fi
BOOST_CONTEXT_ARCHIVE="$(find "$BUILD_DIR/external/boost" -type f -name libboost_context.a -print -quit)"
if [[ -z "$BOOST_CONTEXT_ARCHIVE" ]]; then
    echo "Could not find Hermes Boost.Context archive under $BUILD_DIR/external/boost"
    exit 1
fi
cp "$BOOST_CONTEXT_ARCHIVE" "$INSTALL_DIR/lib/libboost_context.a"
if [[ ! -f "$BUILD_DIR/jsi/libjsi.a" ]]; then
    echo "Could not find Hermes JSI archive at $BUILD_DIR/jsi/libjsi.a"
    exit 1
fi
cp "$BUILD_DIR/jsi/libjsi.a" "$INSTALL_DIR/lib/libjsi.a"

if [[ -f "$BUILD_DIR/bin/hermesc" ]]; then
    cp "$BUILD_DIR/bin/hermesc" "$INSTALL_DIR/bin/"
else
    echo "Could not find hermesc in $BUILD_DIR/bin"
    exit 1
fi

# Public headers used by ibex-runtime build.rs.
# Preserve include shapes expected by Hermes headers:
#   <jsi/...> and <hermes/...>
mkdir -p "$INSTALL_DIR/include/jsi" "$INSTALL_DIR/include/hermes"
cp -R "$SRC_DIR/API/jsi/jsi/"* "$INSTALL_DIR/include/jsi/"
cp -R "$SRC_DIR/API/hermes/"* "$INSTALL_DIR/include/hermes/"
cp -R "$SRC_DIR/public/hermes/Public" "$INSTALL_DIR/include/hermes/"

# Install into repo conventions used by build.rs
mkdir -p "$LINUX_LIB_DIR" "$LINUX_HEADERS_DIR" "$TOOLS_DIR"
rm -rf "$LINUX_HEADERS_DIR"
mkdir -p "$LINUX_HEADERS_DIR"
cp -R "$INSTALL_DIR/include/"* "$LINUX_HEADERS_DIR/"
cp -f "$INSTALL_DIR/lib/libhermesvm.so" "$LINUX_LIB_DIR/"
cp -f "$INSTALL_DIR/lib/libhermesvm_a.a" "$LINUX_LIB_DIR/"
cp -f "$INSTALL_DIR/lib/libjsi.a" "$LINUX_LIB_DIR/"
cp -f "$INSTALL_DIR/lib/libboost_context.a" "$LINUX_LIB_DIR/"
rm -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" \
    "$LINUX_LIB_DIR/hermes-profile-provenance.json"
LINUX_CACHE_KEY="$(ibex_hermes_linux_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}")"
echo "Source cache key: $LINUX_CACHE_KEY"
ibex_write_source_patched_profile_receipt \
    "$INSTALL_DIR/lib/libhermesvm.so" \
    "$INSTALL_DIR/lib/hermes-profile-provenance.json" \
    "$HERMES_VERSION" \
    "$LINUX_CACHE_KEY"
if [[ -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" ]]; then
    cp -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" "$LINUX_LIB_DIR/"
else
    echo "[provenance] custom Hermes source build has no reviewed profile receipt." >&2
fi
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) HERMESC_ARCH="x64" ;;
    arm64|aarch64) HERMESC_ARCH="arm64" ;;
    *) HERMESC_ARCH="$ARCH" ;;
esac
cp -f "$INSTALL_DIR/bin/hermesc" "$TOOLS_DIR/hermesc-linux-$HERMESC_ARCH"

echo ""
echo "Installed Linux Hermes artifacts:"
echo "  headers: $LINUX_HEADERS_DIR"
echo "  libs:    $LINUX_LIB_DIR"
echo "  hermesc: $TOOLS_DIR/hermesc-linux-$HERMESC_ARCH"
echo ""
echo "Suggested env (optional):"
echo "  export HERMES_INCLUDE_DIR=$LINUX_HEADERS_DIR"
echo "  export HERMES_LIB_DIR=$LINUX_LIB_DIR"
