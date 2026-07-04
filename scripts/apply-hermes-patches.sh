#!/usr/bin/env bash

# @ref LLP 0013#upstream-tracking — apply the carried Hermes patch stack.
#
# The pin (hermes-version.sh) plus this ordered patch series *is* the fork
# (the Electron model at small scale): there is no separate long-lived fork
# repository. Each patch under patches/hermes/ carries a class header
# (A=additive-file / B=insertion-point / C=surgical-semantic). Class A/B rebase
# mechanically; Class C is re-read against the surrounding upstream change.
#
# Usage: apply-hermes-patches.sh <hermes-source-dir>
# Idempotent: skips patches that are already applied.

set -euo pipefail

HERMES_SRC="${1:?usage: apply-hermes-patches.sh <hermes-source-dir>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PATCH_DIR="$PROJECT_ROOT/patches/hermes"

if [[ ! -d "$PATCH_DIR" ]]; then
  echo "[patches] no patches/hermes directory; nothing to apply"
  exit 0
fi

shopt -s nullglob
patches=("$PATCH_DIR"/*.patch)
if [[ ${#patches[@]} -eq 0 ]]; then
  echo "[patches] no .patch files in $PATCH_DIR"
  exit 0
fi

cd "$HERMES_SRC"
for patch in "${patches[@]}"; do
  name="$(basename "$patch")"
  if git apply --reverse --check "$patch" >/dev/null 2>&1; then
    echo "[patches] already applied: $name"
    continue
  fi
  if ! git apply --check "$patch" >/dev/null 2>&1; then
    echo "[patches] ERROR: $name does not apply cleanly to this Hermes checkout." >&2
    echo "[patches] The pin may have drifted; see LLP 0013 pin-bump runbook." >&2
    exit 1
  fi
  echo "[patches] applying: $name"
  git apply "$patch"
done
echo "[patches] applied ${#patches[@]} patch(es)"
