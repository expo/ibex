#!/usr/bin/env bash
#
# package-hermes-linux-artifact.sh
# Package Linux Hermes artifacts into a versioned tarball.
#
# Expected inputs (produced by scripts/build-hermes-linux.sh):
#   linux/hermes-headers/
#   linux/lib/libhermesvm.so
#   linux/lib/libhermesvm_a.a
#   linux/lib/libjsi.a
#   linux/lib/libboost_context.a
#   linux/lib/hermes-profile-provenance.json
#   tools/hermes/hermesc-linux-<arch>
#   tools/hermes/hermes-linux-<arch>
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
HERMES_PATH="$PROJECT_ROOT/tools/hermes/hermes-linux-$ARCH"
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
if [[ ! -f "$HERMES_PATH" ]]; then
  echo "Missing Hermes VM CLI: $HERMES_PATH" >&2
  exit 1
fi

SHARED_LIB="$LIB_DIR/libhermesvm.so"
STATIC_LIB="$LIB_DIR/libhermesvm_a.a"
JSI_LIB="$LIB_DIR/libjsi.a"
BOOST_CONTEXT_LIB="$LIB_DIR/libboost_context.a"
PROFILE_RECEIPT="$LIB_DIR/hermes-profile-provenance.json"
if [[ ! -f "$SHARED_LIB" || ! -f "$STATIC_LIB" || ! -f "$JSI_LIB" || ! -f "$BOOST_CONTEXT_LIB" || ! -f "$PROFILE_RECEIPT" ]]; then
  echo "Missing libhermesvm.so, libhermesvm_a.a, libjsi.a, libboost_context.a, or Hermes profile receipt in $LIB_DIR" >&2
  exit 1
fi

PACKAGE_NAME="exact-hermes-linux-${ARCH}-${VERSION}"
STAGE_DIR="$(mktemp -d)"
PKG_DIR="$STAGE_DIR/$PACKAGE_NAME"

mkdir -p "$PKG_DIR/lib" "$PKG_DIR/include" "$PKG_DIR/bin"
cp -R "$HEADERS_DIR/"* "$PKG_DIR/include/"
cp "$SHARED_LIB" "$STATIC_LIB" "$JSI_LIB" "$BOOST_CONTEXT_LIB" "$PROFILE_RECEIPT" "$PKG_DIR/lib/"
cp "$HERMESC_PATH" "$PKG_DIR/bin/hermesc"
# @ref LLP 0005#bytecode-precompilation-hermesc — ship the independent runtime-side HBC version probe with hermesc
cp "$HERMES_PATH" "$PKG_DIR/bin/hermes"
chmod +x "$PKG_DIR/bin/hermesc" "$PKG_DIR/bin/hermes"

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
  "shared_lib_file": "$(basename "$SHARED_LIB")",
  "static_lib_file": "$(basename "$STATIC_LIB")",
  "jsi_lib_file": "$(basename "$JSI_LIB")",
  "boost_context_lib_file": "$(basename "$BOOST_CONTEXT_LIB")"
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
