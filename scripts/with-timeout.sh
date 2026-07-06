#!/usr/bin/env bash
# Run a command under a wall-clock timeout, portably.
# @ref LLP 0017#3-standardize-timeout-and-directory-setup-on-build-machines —
# agent playbooks call this instead of spelling `timeout`/`gtimeout` directly,
# which differ across Linux (coreutils `timeout`) and macOS (Homebrew
# `gtimeout`).
#
# Usage: scripts/with-timeout.sh DURATION command [args...]
#   DURATION is any GNU timeout duration, e.g. 600, 10m, 1h.
#
# Exit status is the command's, or 124 if it timed out (per GNU timeout), or
# 127 if no timeout binary is available.
set -euo pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] || [ "$#" -lt 2 ]; then
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  [ "$#" -lt 2 ] && exit 2
  exit 0
fi

duration="$1"
shift

if command -v timeout >/dev/null 2>&1; then
  exec timeout "$duration" "$@"
elif command -v gtimeout >/dev/null 2>&1; then
  exec gtimeout "$duration" "$@"
fi

echo "error: no timeout binary found. Install GNU coreutils:" >&2
echo "  macOS:  brew install coreutils   (provides gtimeout)" >&2
echo "  Linux:  timeout ships with coreutils" >&2
exit 127
