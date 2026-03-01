#!/usr/bin/env bash
#
# package-hermes-linux-artifact.sh
# Package Linux Hermes artifacts into a versioned tarball.
#
# Expected inputs (produced by scripts/build-hermes-linux.sh):
#   linux/hermes-headers/
#   linux/lib/libhermesvm.{so|a}
#   tools/hermes/hermesc-linux-<arch>
#
# Usage:
#   ./scripts/package-hermes-linux-artifact.sh
#   ./scripts/package-hermes-linux-artifact.sh --version v0.1.0
#   ./scripts/package-hermes-linux-artifact.sh --output-dir dist
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$ARCH_RAW" ;;
esac

HERMESC_PATH="$PROJECT_ROOT/tools/hermes/hermesc-linux-$ARCH"
HEADERS_DIR="$PROJECT_ROOT/linux/hermes-headers"
LIB_DIR="$PROJECT_ROOT/linux/lib"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/exact/hermes-linux"
HERMES_SRC_DIR="$CACHE_ROOT/hermes-src"

if [[ -z "$VERSION" ]]; then
  if [[ -d "$HERMES_SRC_DIR/.git" ]]; then
    VERSION="$(git -C "$HERMES_SRC_DIR" rev-parse --short=12 HEAD)"
  else
    VERSION="unknown"
  fi
fi

if [[ ! -d "$HEADERS_DIR" ]]; then
  echo "Missing headers directory: $HEADERS_DIR" >&2
  exit 1
fi
if [[ ! -d "$LIB_DIR" ]]; then
  echo "Missing library directory: $LIB_DIR" >&2
  exit 1
fi
if [[ ! -f "$HERMESC_PATH" ]]; then
  echo "Missing hermesc binary: $HERMESC_PATH" >&2
  exit 1
fi

LIB_FILE=""
if [[ -f "$LIB_DIR/libhermesvm.so" ]]; then
  LIB_FILE="$LIB_DIR/libhermesvm.so"
elif [[ -f "$LIB_DIR/libhermesvm.a" ]]; then
  LIB_FILE="$LIB_DIR/libhermesvm.a"
else
  echo "Missing libhermesvm.so/.a in $LIB_DIR" >&2
  exit 1
fi

PACKAGE_NAME="exact-hermes-linux-${ARCH}-${VERSION}"
STAGE_DIR="$(mktemp -d)"
PKG_DIR="$STAGE_DIR/$PACKAGE_NAME"

mkdir -p "$PKG_DIR/lib" "$PKG_DIR/include" "$PKG_DIR/bin"
cp -R "$HEADERS_DIR/"* "$PKG_DIR/include/"
cp "$LIB_FILE" "$PKG_DIR/lib/"
cp "$HERMESC_PATH" "$PKG_DIR/bin/hermesc"
chmod +x "$PKG_DIR/bin/hermesc"

HERMES_COMMIT="unknown"
if [[ -d "$HERMES_SRC_DIR/.git" ]]; then
  HERMES_COMMIT="$(git -C "$HERMES_SRC_DIR" rev-parse HEAD)"
fi

cat > "$PKG_DIR/metadata.json" <<EOF
{
  "name": "$PACKAGE_NAME",
  "platform": "linux",
  "arch": "$ARCH",
  "version": "$VERSION",
  "hermes_commit": "$HERMES_COMMIT",
  "lib_file": "$(basename "$LIB_FILE")"
}
EOF

mkdir -p "$OUTPUT_DIR"
ARCHIVE_PATH="$OUTPUT_DIR/$PACKAGE_NAME.tar.gz"
(
  cd "$STAGE_DIR"
  tar -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"
)
sha256sum "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"

rm -rf "$STAGE_DIR"

echo "Packaged Hermes Linux artifact:"
echo "  $ARCHIVE_PATH"
echo "  $ARCHIVE_PATH.sha256"
