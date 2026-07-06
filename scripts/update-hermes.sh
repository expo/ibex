#!/usr/bin/env bash
#
# Update local Apple Hermes artifacts for Ibex.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/hermes-version.sh"

if [[ $# -eq 0 ]]; then
  # Pinned commit by default; the branch name moves (ENG-23092).
  set -- "$IBEX_HERMES_BUILD_REF"
fi

exec "$SCRIPT_DIR/build-hermes.sh" "$@"
