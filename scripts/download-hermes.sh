#!/usr/bin/env bash
#
# Install Hermes runtime artifacts for Ibex.
#
# Usage:
#   ./scripts/download-hermes.sh
#   HERMES_VERSION=260318099.0.0-stable ./scripts/download-hermes.sh
#
# Historical Hermes releases shipped GitHub tarballs for Darwin. The current
# 260318099.0.0 stable release is exposed as a source branch, so this wrapper
# delegates to the source builders used by the platform-specific scripts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/hermes-version.sh"

# Default to the pinned Hermes commit — the stable branch name moves under
# cold clones (ENG-23092).
HERMES_VERSION="${HERMES_VERSION:-$IBEX_HERMES_BUILD_REF}"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"

echo "=== Hermes Install Script ==="
echo "Source ref: $HERMES_VERSION"
echo ""

case "$PLATFORM" in
  linux)
    exec "$SCRIPT_DIR/build-hermes-linux.sh" "$HERMES_VERSION"
    ;;
  darwin)
    exec "$SCRIPT_DIR/build-hermes.sh" "$HERMES_VERSION"
    ;;
  *)
    echo "Unsupported platform: $PLATFORM" >&2
    echo "Set HERMES_INCLUDE_DIR and HERMES_LIB_DIR manually for this target." >&2
    exit 1
    ;;
esac
