#!/bin/bash
#
# build-hermes.sh
# Builds Hermes from source for iOS using their native build scripts
#
# Usage:
#   ./scripts/build-hermes.sh                      # Build latest static_h (default branch)
#   ./scripts/build-hermes.sh v0.13.0              # Build specific tag
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

# Configuration
# Note: Hermes uses "static_h" as their default branch, not "main"
HERMES_VERSION="static_h"
CACHE_DIR="$HOME/.cache/exact/hermes"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"
CLEAN_CACHE=false

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
    if [[ "$version" == "static_h" || "$version" == "main" ]]; then
        # Get latest commit from static_h branch (first 12 chars)
        curl -s "https://api.github.com/repos/facebook/hermes/commits/static_h" | grep '"sha"' | head -1 | cut -d'"' -f4 | cut -c1-12
    else
        # Use version as-is (tag or commit)
        echo "$version"
    fi
}

VERSION_KEY=$(resolve_version "$HERMES_VERSION")
VERSION_CACHE="$CACHE_DIR/${VERSION_KEY}${DEBUG_SUFFIX}"

echo "=== Hermes Build Script ==="
echo "Version: $HERMES_VERSION"
echo "Cache key: $VERSION_KEY"
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

    # Copy headers
    if [ -d "$VERSION_CACHE/include" ]; then
        rm -rf "$FRAMEWORKS_DIR/hermes-headers"
        mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
        cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"
    fi

    # Copy hermesc
    if [ -f "$VERSION_CACHE/bin/hermesc" ]; then
        mkdir -p "$PROJECT_ROOT/tools/hermes"
        cp "$VERSION_CACHE/bin/hermesc" "$PROJECT_ROOT/tools/hermes/"
        echo "[✓] hermesc installed"
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
git fetch origin
if [[ "$HERMES_VERSION" == "static_h" || "$HERMES_VERSION" == "main" ]]; then
    git checkout origin/static_h
else
    git checkout "$HERMES_VERSION" 2>/dev/null || git checkout "origin/$HERMES_VERSION"
fi

ACTUAL_COMMIT=$(git rev-parse HEAD | cut -c1-12)
echo "Building commit: $ACTUAL_COMMIT"
echo ""

# Clean previous builds
rm -rf destroot build_host_hermesc build_iphoneos build_iphonesimulator build_macosx

echo "=== Building Hermes for iOS ==="
echo ""

NUM_CORES=$(sysctl -n hw.ncpu)

# Build host hermesc first (force macOS SDK to avoid visionOS defaults)
echo "Building host hermesc..."
# Note: HAVE_CXX_ATOMICS*_WITHOUT_LIB=ON works around a CMake detection issue on macOS
cmake -S . -B build_host_hermesc -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT:STRING="macosx" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$MAC_DEPLOYMENT_TARGET" \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
cmake --build ./build_host_hermesc --target hermesc -j "${NUM_CORES}"

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
cp -R "$HERMES_SRC/destroot/include" "$VERSION_CACHE/"
mkdir -p "$VERSION_CACHE/bin"
cp "$HERMES_SRC/destroot/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true
cp "$HERMES_SRC/build_host_hermesc/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true

# Install to project
echo ""
echo "=== Installing to project ==="
mkdir -p "$FRAMEWORKS_DIR"
rm -rf "$FRAMEWORKS_DIR/hermes.xcframework"
cp -R "$VERSION_CACHE/hermesvm.xcframework" "$FRAMEWORKS_DIR/hermes.xcframework"

rm -rf "$FRAMEWORKS_DIR/hermes-headers"
mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"

mkdir -p "$PROJECT_ROOT/tools/hermes"
cp "$VERSION_CACHE/bin/hermesc" "$PROJECT_ROOT/tools/hermes/" 2>/dev/null || true

echo ""
echo "=== Build Complete ==="
echo ""
echo "Installed:"
echo "  Framework: $FRAMEWORKS_DIR/hermes.xcframework"
echo "  Headers:   $FRAMEWORKS_DIR/hermes-headers/"
echo "  CLI:       $PROJECT_ROOT/tools/hermes/hermesc"
echo ""
echo "Cached at: $VERSION_CACHE"
echo ""
echo "Note: The framework is named 'hermesvm' internally but installed as 'hermes'"
echo "      for compatibility with the existing project structure."
echo ""
