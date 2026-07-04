#!/bin/bash
#
# Build the Hermes macOS framework required by Cargo tests.
#
# The upstream Hermes 0.11 release xcframework contains iOS and Mac Catalyst
# slices, but not a pure macOS framework. Cargo builds target
# arm64/x86_64-apple-macosx, so they need a macOS hermes.framework.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

HERMES_VERSION="${HERMES_VERSION:-$IBEX_HERMES_SOURCE_REF}"
FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"
DEST_FRAMEWORK="$FRAMEWORKS_DIR/macosx/hermes.framework"
TEMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "build-hermes-macos.sh only runs on macOS"
    exit 1
fi

if [[ -d "$DEST_FRAMEWORK" ]]; then
    echo "[ok] macOS Hermes framework already exists at $DEST_FRAMEWORK"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to build Hermes"
    exit 1
fi

if ! command -v ninja >/dev/null 2>&1; then
    echo "ninja is required to build Hermes"
    exit 1
fi

cmake_major_version() {
    "$1" --version | awk '/version/ { split($3, parts, "."); print parts[1]; exit }'
}

resolve_cmake() {
    if command -v cmake >/dev/null 2>&1; then
        local cmake_bin
        cmake_bin="$(command -v cmake)"
        local major
        major="$(cmake_major_version "$cmake_bin")"
        if [[ -n "$major" && "$major" -lt 4 ]]; then
            echo "$cmake_bin"
            return
        fi
    fi

    echo "[i] Installing temporary CMake 3.27 for Hermes 0.11 compatibility" >&2
    python3 -m venv "$TEMP_DIR/cmake-venv"
    "$TEMP_DIR/cmake-venv/bin/pip" install "cmake==3.27.9"
    echo "$TEMP_DIR/cmake-venv/bin/cmake"
}

case "$(uname -m)" in
    arm64|aarch64) BUILD_ARCH="arm64" ;;
    x86_64|amd64) BUILD_ARCH="x86_64" ;;
    *)
        echo "Unsupported macOS architecture: $(uname -m)"
        exit 1
        ;;
esac

CMAKE_BIN="$(resolve_cmake)"
export PATH="$(dirname "$CMAKE_BIN"):$PATH"

HERMES_REF="$HERMES_VERSION"
if [[ "$HERMES_REF" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HERMES_REF="v$HERMES_REF"
fi

echo "[i] Cloning Hermes $HERMES_REF"
git clone --depth 1 --branch "$HERMES_REF" https://github.com/facebook/hermes.git "$TEMP_DIR/hermes" 2>/dev/null

cd "$TEMP_DIR/hermes"

# @ref LLP 0013#upstream-tracking — apply the carried Hermes patch stack (the
# pin + patch series is the fork). No-op when patches/hermes is empty.
"$SCRIPT_DIR/apply-hermes-patches.sh" "$TEMP_DIR/hermes"

echo "[i] Building host hermesc"
python3 ./utils/build/configure.py build_host_hermesc
cmake --build ./build_host_hermesc --target hermesc

echo "[i] Building macOS Hermes framework for $BUILD_ARCH"
python3 ./utils/build/configure.py \
    --distribute \
    --build-system=Ninja \
    --cmake-flags " -DHERMES_APPLE_TARGET_PLATFORM:STRING=macosx -DCMAKE_OSX_ARCHITECTURES:STRING=$BUILD_ARCH -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING=14.0 -DHERMES_ENABLE_DEBUGGER:BOOLEAN=false -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false -DHERMES_ENABLE_BITCODE:BOOLEAN=false -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true -DHERMES_BUILD_APPLE_DSYM:BOOLEAN=false -DHERMES_ENABLE_TOOLS:BOOLEAN=false -DIMPORT_HERMESC:PATH=$PWD/build_host_hermesc/ImportHermesc.cmake -DCMAKE_INSTALL_PREFIX:PATH=../destroot" \
    build_macosx

(cd build_macosx && ninja install/strip)

mkdir -p "$FRAMEWORKS_DIR/macosx"
cp -R "$TEMP_DIR/hermes/destroot/Library/Frameworks/macosx/hermes.framework" "$FRAMEWORKS_DIR/macosx/"

echo "[ok] macOS Hermes framework installed at $DEST_FRAMEWORK"
