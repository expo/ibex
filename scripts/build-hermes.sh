#!/bin/bash
#
# build-hermes.sh
# Builds Hermes from source for iOS using their native build scripts
#
# Usage:
#   ./scripts/build-hermes.sh                      # Build pinned stable Hermes release
#   ./scripts/build-hermes.sh --latest             # Build latest static_h head
#   ./scripts/build-hermes.sh 260318099.0.0-stable # Build specific branch
#   ./scripts/build-hermes.sh v0.13.0              # Build specific tag
#   ./scripts/build-hermes.sh <commit>             # Build specific commit
#   ./scripts/build-hermes.sh --release            # Build without debugger
#   ./scripts/build-hermes.sh --debug              # Force debugger on
#   ./scripts/build-hermes.sh --clean              # Clean cache and rebuild
#
# The built xcframework is cached at:
#   ~/.cache/exact/hermes/<version>/
#
# After building, it's automatically copied to:
#   ios/Frameworks/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

# Configuration
# Default to the pinned Hermes commit (scripts/hermes-version.sh) — the stable
# branch name moves under cold clones (ENG-23092). Use --latest only when you
# explicitly want the moving static_h development head.
DEFAULT_HERMES_REF="$IBEX_HERMES_BUILD_REF"
HERMES_VERSION="${HERMES_VERSION:-$DEFAULT_HERMES_REF}"
CACHE_DIR="$HOME/.cache/exact/hermes"
FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"
CLEAN_CACHE=false
HOST_ARCH_RAW="$(uname -m)"
case "$HOST_ARCH_RAW" in
    x86_64|amd64) HOST_ARCH="x64" ;;
    arm64|aarch64) HOST_ARCH="arm64" ;;
    *) HOST_ARCH="$HOST_ARCH_RAW" ;;
esac
HERMESC_DEST="$PROJECT_ROOT/tools/hermes/hermesc-macos-$HOST_ARCH"
MACOS_FRAMEWORK_DEST="$FRAMEWORKS_DIR/hermesvm.framework"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --latest)
            HERMES_VERSION="static_h"
            shift
            ;;
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
        *)
            HERMES_VERSION="$1"
            shift
            ;;
    esac
done
DEBUG_SUFFIX=""
if [[ "$HERMES_DEBUGGER" == "1" || "$HERMES_DEBUGGER" == "true" || "$HERMES_DEBUGGER" == "TRUE" || "$HERMES_DEBUGGER" == "yes" || "$HERMES_DEBUGGER" == "YES" ]]; then
    DEBUG_SUFFIX="-debug"
fi

is_truthy() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

verify_debugger_symbols() {
    local framework_dir="$1"
    local binary="$framework_dir/Versions/1/hermesvm"
    if ! is_truthy "$HERMES_DEBUGGER"; then
        return
    fi
    if [ ! -f "$binary" ]; then
        echo "[✗] Expected Hermes macOS binary at $binary"
        exit 1
    fi
    if ! nm -gU "$binary" 2>/dev/null | grep -q "AsyncDebuggerAPI"; then
        echo "[✗] Hermes macOS framework was built without debugger symbols"
        echo "    Missing AsyncDebuggerAPI in $binary"
        exit 1
    fi
    echo "[✓] Verified Hermes debugger symbols in $(basename "$framework_dir")"
}

# iOS deployment target (minimum iOS version)
export IOS_DEPLOYMENT_TARGET="15.0"
export MAC_DEPLOYMENT_TARGET="12.0"
export XROS_DEPLOYMENT_TARGET="1.0"

# Handle --clean flag
if [ "$CLEAN_CACHE" = true ]; then
    echo "Cleaning Hermes cache..."
    rm -rf "$CACHE_DIR"
    echo "Done. Run again without --clean to rebuild."
    exit 0
fi

# Resolve version to a cache key
resolve_version() {
    local version="$1"
    local ref="$version"
    if [[ "$version" == "static_h" || "$version" == "main" ]]; then
        ref="static_h"
    fi
    # A full commit SHA is already an exact key; skip the remote lookup.
    if [[ "$version" =~ ^[0-9a-f]{40}$ ]]; then
        echo "${version:0:12}"
        return
    fi
    local remote_sha
    remote_sha="$(git ls-remote https://github.com/facebook/hermes.git \
        "refs/heads/$ref" "refs/tags/$ref" "refs/tags/v$ref" 2>/dev/null \
        | awk 'NR == 1 { print substr($1, 1, 12); exit }')"
    if [[ -n "$remote_sha" ]]; then
        echo "$remote_sha"
    else
        echo "$version"
    fi
}

# The carried patch stack is part of the build identity: the framework the
# cache-hit path installs was built from upstream@SHA *plus* patches/hermes/*.
# Keying only on the upstream SHA let an edited/added patch silently install a
# stale-patched framework ("already built"), greenlighting old enforcement
# semantics in the authenticated CapSec callback/conformance suites. Digest content + filenames so an edit,
# add, remove, or reorder all miss the cache. (ENG-23131; mirrors the
# hashFiles('patches/hermes/**') key compartment-conformance.yml already uses.)
# The digest derivation is shared with download-hermes.sh and the
# hermes-artifacts publish workflow via scripts/hermes-version.sh (ENG-23147).
VERSION_KEY=$(resolve_version "$HERMES_VERSION")
PATCH_DIGEST=$(ibex_hermes_patch_digest)
VERSION_CACHE="$CACHE_DIR/${VERSION_KEY}${DEBUG_SUFFIX}-p${PATCH_DIGEST}"

echo "=== Hermes Build Script ==="
echo "Version: $HERMES_VERSION"
echo "Cache key: $VERSION_KEY (patch stack: $PATCH_DIGEST)"
echo "Debugger suffix: $DEBUG_SUFFIX"
echo "Cache dir: $VERSION_CACHE"
echo "iOS Deployment Target: $IOS_DEPLOYMENT_TARGET"
echo "Hermes Debugger: $HERMES_DEBUGGER"
echo ""

# Check if already built
if [ -d "$VERSION_CACHE/hermesvm.xcframework" ]; then
    echo "[✓] Hermes $VERSION_KEY already built"
    echo ""

    # Copy to project
    echo "Installing to project..."
    mkdir -p "$FRAMEWORKS_DIR"
    rm -rf "$FRAMEWORKS_DIR/hermes.xcframework"
    cp -R "$VERSION_CACHE/hermesvm.xcframework" "$FRAMEWORKS_DIR/hermes.xcframework"
    if [ -d "$VERSION_CACHE/hermesvm.framework" ]; then
        rm -rf "$MACOS_FRAMEWORK_DEST"
        cp -R "$VERSION_CACHE/hermesvm.framework" "$MACOS_FRAMEWORK_DEST"
        verify_debugger_symbols "$MACOS_FRAMEWORK_DEST"
    fi

    # Copy headers
    if [ -d "$VERSION_CACHE/include" ]; then
        rm -rf "$FRAMEWORKS_DIR/hermes-headers"
        mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
        cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"
    fi

    # Copy hermesc / hermes binaries
    if [ -f "$VERSION_CACHE/bin/hermesc" ]; then
        mkdir -p "$PROJECT_ROOT/tools/hermes"
        cp "$VERSION_CACHE/bin/hermesc" "$HERMESC_DEST"
        echo "[✓] hermesc installed"
    fi
    if [ -f "$VERSION_CACHE/bin/hermes" ]; then
        mkdir -p "$PROJECT_ROOT/tools/hermes"
        cp "$VERSION_CACHE/bin/hermes" "$PROJECT_ROOT/tools/hermes/hermes"
        echo "[✓] hermes installed"
    fi

    echo "[✓] Installed to $FRAMEWORKS_DIR"
    exit 0
fi

# Check dependencies
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo "[✗] cmake not found. Install with: brew install cmake"
    exit 1
fi
echo "[✓] cmake: $(cmake --version | head -1)"

if ! command -v ninja &> /dev/null; then
    echo "[!] ninja not found (optional, will use make). Install with: brew install ninja"
fi

if ! xcode-select -p &> /dev/null; then
    echo "[✗] Xcode command line tools not found"
    exit 1
fi
echo "[✓] Xcode: $(xcode-select -p)"

echo ""

# Create cache directory
mkdir -p "$VERSION_CACHE"

# Clone or update Hermes
HERMES_SRC="$CACHE_DIR/hermes-src"

if [ ! -d "$HERMES_SRC/.git" ]; then
    echo "Cloning Hermes repository..."
    rm -rf "$HERMES_SRC"
    git clone https://github.com/facebook/hermes.git "$HERMES_SRC"
fi

cd "$HERMES_SRC"

echo "Checking out $HERMES_VERSION..."
git fetch origin --tags
if [[ "$HERMES_VERSION" == "static_h" || "$HERMES_VERSION" == "main" ]]; then
    git checkout origin/static_h
elif git rev-parse --verify --quiet "origin/$HERMES_VERSION" >/dev/null; then
    git checkout "origin/$HERMES_VERSION"
else
    # A pinned commit may not be reachable from any currently advertised
    # branch/tag (upstream rebases/deletes release branches); GitHub serves
    # explicit SHA fetches, so ask for it directly before checking out.
    if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]] \
        && ! git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null; then
        git fetch origin "$HERMES_VERSION"
    fi
    git checkout "$HERMES_VERSION"
fi

ACTUAL_COMMIT=$(git rev-parse HEAD | cut -c1-12)
echo "Building commit: $ACTUAL_COMMIT"
echo ""

# @ref LLP 0013#upstream-tracking — restore a pristine tree (this cache is
# reused across builds), then apply the carried Hermes patch stack.
git checkout -- . 2>/dev/null || true
git clean -fdq -- include lib 2>/dev/null || true
"$SCRIPT_DIR/apply-hermes-patches.sh" "$HERMES_SRC"

# Clean previous builds
rm -rf destroot build_host_hermesc build_iphoneos build_iphonesimulator build_macosx

echo "=== Building Hermes for iOS ==="
echo ""

NUM_CORES=$(sysctl -n hw.ncpu)

# Build host hermesc first (force macOS SDK to avoid visionOS defaults)
echo "Building host hermesc..."
# Note: HAVE_CXX_ATOMICS*_WITHOUT_LIB=ON works around a CMake detection issue on macOS
#
# HERMES_ENABLE_TEST_SUITE=false: the host hermesc build only needs the
# compiler; disabling the test suite skips add_subdirectory(unittests). Old
# Hermes unittests mix plain and keyword target_link_libraries signatures,
# which CMake 4.x hard-errors on ("all uses ... must be either all-keyword or
# all-plain" — HermesADTTests/HermesOptimizerTests via cmake/modules/Lit.cmake),
# breaking a cold-clone Hermes bootstrap on a machine with Homebrew CMake 4.x
# and no prebuilt artifacts. The three device/simulator/macos configures below
# already pass this flag; the host configure was the only one missing it.
# (ENG-23077, ported from the exact-side ENG-22565 fix.)
cmake -S . -B build_host_hermesc -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT:STRING="macosx" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$MAC_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
cmake --build ./build_host_hermesc --target hermesc -j "${NUM_CORES}"
cmake --build ./build_host_hermesc --target hermes -j "${NUM_CORES}"

# Build for iOS device
echo ""
echo "Building for iphoneos (arm64)..."
cmake -S . -B build_iphoneos \
    -DHERMES_APPLE_TARGET_PLATFORM:STRING="iphoneos" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$IOS_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_DEBUGGER:BOOLEAN="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL:BOOLEAN=true \
    -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false \
    -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHERMES_ENABLE_BITCODE:BOOLEAN=false \
    -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true \
    -DHERMES_BUILD_SHARED_JSI:BOOLEAN=false \
    -DIMPORT_HOST_COMPILERS:PATH="$PWD/build_host_hermesc/ImportHostCompilers.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel

# Build bytecode include first (required dependency)
cmake --build ./build_iphoneos --target ExtensionsBytecodeInclude -j 1
cmake --build ./build_iphoneos --target hermesvm -j "${NUM_CORES}"

mkdir -p destroot/Library/Frameworks/iphoneos
cp -R ./build_iphoneos/lib/hermesvm.framework destroot/Library/Frameworks/iphoneos/

# Build for iOS simulator
echo ""
echo "Building for iphonesimulator (arm64, x86_64)..."
cmake -S . -B build_iphonesimulator \
    -DHERMES_APPLE_TARGET_PLATFORM:STRING="iphonesimulator" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="x86_64;arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$IOS_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_DEBUGGER:BOOLEAN="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL:BOOLEAN=true \
    -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false \
    -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHERMES_ENABLE_BITCODE:BOOLEAN=false \
    -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true \
    -DHERMES_BUILD_SHARED_JSI:BOOLEAN=false \
    -DIMPORT_HOST_COMPILERS:PATH="$PWD/build_host_hermesc/ImportHostCompilers.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel

# Build bytecode include first (required dependency)
cmake --build ./build_iphonesimulator --target ExtensionsBytecodeInclude -j 1
cmake --build ./build_iphonesimulator --target hermesvm -j "${NUM_CORES}"

mkdir -p destroot/Library/Frameworks/iphonesimulator
cp -R ./build_iphonesimulator/lib/hermesvm.framework destroot/Library/Frameworks/iphonesimulator/

# Build for macOS
echo ""
echo "Building for macOS (arm64, x86_64)..."
# Note: We add flags to suppress visionOS availability errors in newer SDKs
cmake -S . -B build_macosx \
    -DHERMES_APPLE_TARGET_PLATFORM:STRING="macosx" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="x86_64;arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$MAC_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_DEBUGGER:BOOLEAN="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL:BOOLEAN=true \
    -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false \
    -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHERMES_ENABLE_BITCODE:BOOLEAN=false \
    -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true \
    -DHERMES_BUILD_SHARED_JSI:BOOLEAN=false \
    -DIMPORT_HOST_COMPILERS:PATH="$PWD/build_host_hermesc/ImportHostCompilers.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_C_FLAGS="-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability" \
    -DCMAKE_CXX_FLAGS="-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability"

# Build bytecode include first (required dependency)
cmake --build ./build_macosx --target ExtensionsBytecodeInclude -j 1
cmake --build ./build_macosx --target hermesvm -j "${NUM_CORES}"

mkdir -p destroot/Library/Frameworks/macosx
cp -R ./build_macosx/lib/hermesvm.framework destroot/Library/Frameworks/macosx/

# Copy headers
mkdir -p destroot/include/hermes/Public
cp public/hermes/Public/*.h destroot/include/hermes/Public/
mkdir -p destroot/include/hermes
cp API/hermes/*.h destroot/include/hermes/
mkdir -p destroot/include/hermes/cdp
cp API/hermes/cdp/*.h destroot/include/hermes/cdp/
mkdir -p destroot/include/jsi
cp API/jsi/jsi/*.h destroot/include/jsi/

# Create xcframework from iOS, simulator, and macOS
echo ""
echo "Creating xcframework..."
mkdir -p destroot/Library/Frameworks/universal
xcodebuild -create-xcframework \
    -framework "destroot/Library/Frameworks/iphoneos/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/iphonesimulator/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/macosx/hermesvm.framework" \
    -output "destroot/Library/Frameworks/universal/hermesvm.xcframework"

# Copy results to cache
echo ""
echo "Caching build results..."
cp -R "$HERMES_SRC/destroot/Library/Frameworks/universal/hermesvm.xcframework" "$VERSION_CACHE/"
cp -R "$HERMES_SRC/build_macosx/lib/hermesvm.framework" "$VERSION_CACHE/"
cp -R "$HERMES_SRC/destroot/include" "$VERSION_CACHE/"
mkdir -p "$VERSION_CACHE/bin"
cp "$HERMES_SRC/destroot/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true
cp "$HERMES_SRC/build_host_hermesc/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true
cp "$HERMES_SRC/build_host_hermesc/bin/hermes" "$VERSION_CACHE/bin/" 2>/dev/null || true

# Install to project
echo ""
echo "=== Installing to project ==="
mkdir -p "$FRAMEWORKS_DIR"
rm -rf "$FRAMEWORKS_DIR/hermes.xcframework"
cp -R "$VERSION_CACHE/hermesvm.xcframework" "$FRAMEWORKS_DIR/hermes.xcframework"
rm -rf "$MACOS_FRAMEWORK_DEST"
cp -R "$VERSION_CACHE/hermesvm.framework" "$MACOS_FRAMEWORK_DEST"
verify_debugger_symbols "$MACOS_FRAMEWORK_DEST"

rm -rf "$FRAMEWORKS_DIR/hermes-headers"
mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"

mkdir -p "$PROJECT_ROOT/tools/hermes"
cp "$VERSION_CACHE/bin/hermesc" "$HERMESC_DEST" 2>/dev/null || true
cp "$VERSION_CACHE/bin/hermes" "$PROJECT_ROOT/tools/hermes/hermes" 2>/dev/null || true

echo ""
echo "=== Build Complete ==="
echo ""
echo "Installed:"
echo "  Framework: $FRAMEWORKS_DIR/hermes.xcframework"
echo "  macOS FW:  $MACOS_FRAMEWORK_DEST"
echo "  Headers:   $FRAMEWORKS_DIR/hermes-headers/"
echo "  CLI:       $HERMESC_DEST"
echo ""
echo "Cached at: $VERSION_CACHE"
echo ""
echo "Note: The framework is named 'hermesvm' internally but installed as 'hermes'"
echo "      for compatibility with the existing project structure."
echo ""
