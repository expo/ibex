#!/usr/bin/env bash
#
# Update local Apple Hermes artifacts for Ibex.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/hermes-version.sh"

if [[ $# -eq 0 ]]; then
  set -- "$IBEX_HERMES_SOURCE_REF"
fi

exec "$SCRIPT_DIR/build-hermes.sh" "$@"
