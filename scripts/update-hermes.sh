#!/bin/bash
set -e

# Script to extract Hermes V1 from React Native 0.84
# This gets the production-ready, pre-built Hermes V1 with native ES6+ support

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMP_DIR="$PROJECT_ROOT/tmp/hermes-extract"
FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"

echo "🚀 Extracting Hermes V1 from React Native 0.84..."
echo ""

# Clean up any previous temp directory
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Create a minimal RN 0.84 project to get Hermes
echo "📦 Creating temporary React Native 0.84 project..."
npx --yes @react-native-community/cli@latest init HermesExtract --version 0.84.0 --skip-install

cd HermesExtract

# Install dependencies (this will download Hermes via CocoaPods)
echo ""
echo "📥 Installing iOS dependencies (this downloads Hermes V1)..."
cd ios

# Install bundler gems (including CocoaPods)
if [ -f "Gemfile" ]; then
    echo "   Installing Ruby dependencies..."
    bundle install --quiet
    POD_CMD="bundle exec pod"
else
    POD_CMD="pod"
fi

# Run pod install
echo "   Running pod install (this may take a few minutes)..."
$POD_CMD install

# Check what we got
echo ""
echo "✅ Hermes V1 downloaded! Inspecting..."
HERMES_POD_DIR="Pods/hermes-engine/destroot/Library/Frameworks"

if [ -d "$HERMES_POD_DIR/universal/hermes.xcframework" ]; then
    echo "   Found: $HERMES_POD_DIR/universal/hermes.xcframework"
elif [ -d "$HERMES_POD_DIR/hermes.xcframework" ]; then
    HERMES_POD_DIR="$HERMES_POD_DIR"
    echo "   Found: $HERMES_POD_DIR/hermes.xcframework"
else
    echo "❌ Error: Hermes xcframework not found in expected location"
    echo "   Searched in: $HERMES_POD_DIR"
    echo ""
    echo "Available pods:"
    ls -la Pods/ | grep hermes || echo "No hermes pods found"
    exit 1
fi

# Copy Hermes to our project
echo ""
echo "📋 Copying Hermes V1 to Exact project..."

# Backup old Hermes
if [ -d "$FRAMEWORKS_DIR/hermes.xcframework" ]; then
    BACKUP_DIR="$FRAMEWORKS_DIR/hermes.xcframework.backup.$(date +%Y%m%d_%H%M%S)"
    echo "   Backing up old Hermes to: $BACKUP_DIR"
    mv "$FRAMEWORKS_DIR/hermes.xcframework" "$BACKUP_DIR"
fi

# Copy new Hermes V1
if [ -d "$HERMES_POD_DIR/universal/hermes.xcframework" ]; then
    cp -R "$HERMES_POD_DIR/universal/hermes.xcframework" "$FRAMEWORKS_DIR/"
else
    cp -R "$HERMES_POD_DIR/hermes.xcframework" "$FRAMEWORKS_DIR/"
fi

# Also copy headers if available
if [ -d "Pods/hermes-engine/destroot/include" ]; then
    echo "   Copying Hermes headers..."
    rm -rf "$FRAMEWORKS_DIR/hermes-headers"
    cp -R "Pods/hermes-engine/destroot/include" "$FRAMEWORKS_DIR/hermes-headers"
fi

# Copy CLI tools (hermesc, hermes compiler)
TOOLS_DIR="$PROJECT_ROOT/tools/hermes"
mkdir -p "$TOOLS_DIR"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64) ARCH="x64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) ARCH="$ARCH_RAW" ;;
esac
HERMESC_DEST="$TOOLS_DIR/hermesc-macos-$ARCH"

if [ -d "Pods/hermes-engine/destroot/bin" ]; then
    echo "   Copying Hermes CLI tools (hermesc, etc.)..."
    cp -R Pods/hermes-engine/destroot/bin/* "$TOOLS_DIR/" 2>/dev/null || true
    if [ -f "$TOOLS_DIR/hermesc" ]; then
        mv "$TOOLS_DIR/hermesc" "$HERMESC_DEST"
    fi
fi

# Get version info
echo ""
echo "📊 Hermes V1 Version Info:"
if [ -f "$FRAMEWORKS_DIR/hermes.xcframework/Info.plist" ]; then
    echo "   XCFramework platforms:"
    /usr/libexec/PlistBuddy -c "Print :AvailableLibraries" "$FRAMEWORKS_DIR/hermes.xcframework/Info.plist" 2>/dev/null | grep "SupportedPlatform" | sed 's/^/     /'
fi

# Try to get Hermes version from podspec
POD_VERSION=$(cat ../../HermesExtract/node_modules/react-native/package.json | grep '"version"' | head -1 | sed 's/.*: "\(.*\)",/\1/')
echo "   React Native version: $POD_VERSION"

# Check hermesc version if available
if [ -f "$HERMESC_DEST" ]; then
    chmod +x "$HERMESC_DEST"
    echo "   hermesc tool: Available"
    # Try to get version (may not work depending on hermesc build)
    "$HERMESC_DEST" --version 2>/dev/null || echo "     (version command not available)"
fi

# Clean up
echo ""
echo "🧹 Cleaning up temporary files..."
cd "$PROJECT_ROOT"
rm -rf "$TEMP_DIR"

echo ""
echo "✨ Done! Hermes V1 from React Native 0.84 installed successfully!"
echo ""
echo "📍 Installed to:"
echo "   Framework: $FRAMEWORKS_DIR/hermes.xcframework"
echo "   Headers:   $FRAMEWORKS_DIR/hermes-headers"
echo "   Tools:     $TOOLS_DIR"
echo ""
echo "🔧 Next steps:"
echo "   1. Rebuild Ibex: cargo build --release --bin ibex --features host-http-server,cli-notify"
echo "   2. Test the REPL: cargo run --bin ibex -- repl"
echo "   3. Check performance improvements!"
echo ""
