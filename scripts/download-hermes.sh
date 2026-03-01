#!/bin/bash
#
# download-hermes.sh
# Downloads Hermes runtime and CLI tools for Exact
#
# Usage: ./scripts/download-hermes.sh
#

set -e

HERMES_VERSION="0.11.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
RUNTIME_SHA256="593773e4800c5be3f041162cd18880181153da2e7b0340bf43f0e051b2717a"
CLI_SHA256="b051e3f099023c5d131fcd7b5a6d664e845588db440c9ea8ee0396ade370bf99a"

FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"
TOOLS_DIR="$PROJECT_ROOT/tools/hermes"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

checksum_of() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
        return
    fi
    echo "ERROR: missing sha256sum or shasum"
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    actual="$(checksum_of "$file")"
    if [ -z "$actual" ]; then
        echo "[✗] Unable to verify checksum for $file"
        exit 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "[✗] Checksum mismatch for $file"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        exit 1
    fi
}

echo "=== Hermes Download Script ==="
echo "Version: $HERMES_VERSION"
echo ""

if [[ "$PLATFORM" == "linux" ]]; then
    echo "[i] Linux detected. Building Hermes from source via build-hermes-linux.sh..."
    exec "$SCRIPT_DIR/build-hermes-linux.sh"
fi

# -----------------------------------------------------------------------------
# Download Hermes Runtime (xcframework)
# -----------------------------------------------------------------------------

if [ -d "$FRAMEWORKS_DIR/hermes.xcframework" ]; then
    echo "[✓] hermes.xcframework already exists"
else
    echo "[↓] Downloading Hermes runtime..."

    RUNTIME_URL="https://github.com/facebook/hermes/releases/download/v${HERMES_VERSION}/hermes-runtime-darwin-v${HERMES_VERSION}.tar.gz"
    RUNTIME_TAR="$TEMP_DIR/hermes-runtime.tar.gz"

    curl -L -o "$RUNTIME_TAR" "$RUNTIME_URL"
    verify_sha256 "$RUNTIME_TAR" "$RUNTIME_SHA256"

    echo "[↓] Extracting..."
    mkdir -p "$TEMP_DIR/runtime"
    tar -xzf "$RUNTIME_TAR" -C "$TEMP_DIR/runtime" 2>/dev/null || true

    # Copy xcframework
    mkdir -p "$FRAMEWORKS_DIR"
    cp -R "$TEMP_DIR/runtime/destroot/Library/Frameworks/universal/hermes.xcframework" "$FRAMEWORKS_DIR/"

    echo "[✓] hermes.xcframework installed"
fi

# -----------------------------------------------------------------------------
# Download Hermes Headers (from source)
# -----------------------------------------------------------------------------

if [ -d "$FRAMEWORKS_DIR/hermes-headers/hermes" ] && [ -d "$FRAMEWORKS_DIR/hermes-headers/jsi" ]; then
    echo "[✓] hermes-headers already exists"
else
    echo "[↓] Downloading Hermes headers..."

    HEADERS_DIR="$TEMP_DIR/hermes-src"
    git clone --depth 1 --branch "v${HERMES_VERSION}" https://github.com/facebook/hermes.git "$HEADERS_DIR" 2>/dev/null

    mkdir -p "$FRAMEWORKS_DIR/hermes-headers"

    # Copy API headers (jsi and hermes)
    cp -R "$HEADERS_DIR/API/jsi" "$FRAMEWORKS_DIR/hermes-headers/"
    cp -R "$HEADERS_DIR/API/hermes" "$FRAMEWORKS_DIR/hermes-headers/"

    # Copy public headers
    cp -R "$HEADERS_DIR/public/hermes/Public" "$FRAMEWORKS_DIR/hermes-headers/hermes/"

    echo "[✓] hermes-headers installed"
fi

# -----------------------------------------------------------------------------
# Download Hermes CLI Tools
# -----------------------------------------------------------------------------

if [ -f "$TOOLS_DIR/hermesc" ]; then
    echo "[✓] Hermes CLI tools already exist"
else
    echo "[↓] Downloading Hermes CLI tools..."

    CLI_URL="https://github.com/facebook/hermes/releases/download/v${HERMES_VERSION}/hermes-cli-darwin-v${HERMES_VERSION}.tar.gz"
    CLI_TAR="$TEMP_DIR/hermes-cli.tar.gz"

    curl -L -o "$CLI_TAR" "$CLI_URL"
    verify_sha256 "$CLI_TAR" "$CLI_SHA256"

    echo "[↓] Extracting..."
    mkdir -p "$TOOLS_DIR"
    tar -xzf "$CLI_TAR" -C "$TOOLS_DIR" 2>/dev/null || true

    # Keep only the tools we need
    if [ -f "$TOOLS_DIR/hermesc" ]; then
        # Remove tools we don't need to save space
        rm -f "$TOOLS_DIR/hermes" "$TOOLS_DIR/hdb" "$TOOLS_DIR/hvm" 2>/dev/null || true
        echo "[✓] Hermes CLI tools installed"
    else
        echo "[!] Warning: hermesc not found after extraction"
    fi
fi

# -----------------------------------------------------------------------------
# Verify Installation
# -----------------------------------------------------------------------------

echo ""
echo "=== Verification ==="

if [ -d "$FRAMEWORKS_DIR/hermes.xcframework" ]; then
    SIZE=$(du -sh "$FRAMEWORKS_DIR/hermes.xcframework" | cut -f1)
    echo "[✓] hermes.xcframework: $SIZE"
else
    echo "[✗] hermes.xcframework: MISSING"
fi

if [ -d "$FRAMEWORKS_DIR/hermes-headers" ]; then
    SIZE=$(du -sh "$FRAMEWORKS_DIR/hermes-headers" | cut -f1)
    echo "[✓] hermes-headers: $SIZE"
else
    echo "[✗] hermes-headers: MISSING"
fi

if [ -f "$TOOLS_DIR/hermesc" ]; then
    VERSION=$("$TOOLS_DIR/hermesc" --version 2>&1 | grep "Hermes release" | head -1 || echo "unknown")
    echo "[✓] hermesc: $VERSION"
else
    echo "[✗] hermesc: MISSING"
fi

echo ""
echo "Done!"
