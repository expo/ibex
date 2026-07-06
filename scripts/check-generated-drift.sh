#!/usr/bin/env bash
# Prove every committed generated artifact is current, WITHOUT writing to the
# working tree — safe to wire into CI and a pre-push hook with no dirty-tree race.
# @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check
#
# Two non-mutating strategies, both driven off the package.json scripts (one
# source of truth, shared with regenerate:vendored):
#   * generators that support --check verify in place and write nothing;
#   * the two bundle builders are pointed at a scratch out-dir (last --out wins)
#     and their output is diffed against the committed copy.
# Exits nonzero listing the stale paths and the command to refresh them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun is required to check generated drift (run bun install)" >&2
  exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/ibex-drift.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

stale=()

# --- check-capable generators (verify in place, write nothing) -------------
if ! bun run generate:capability-bits --check >/dev/null 2>&1; then
  stale+=("packages/ibex-runtime-js/src/security/capability-bits.generated.ts")
fi
if ! bun run generate:identity --check >/dev/null 2>&1; then
  stale+=("packages/ibex-runtime-js/src/identity.generated.ts" "src/identity_generated.rs")
fi
if ! bun run generate:modules --check >/dev/null 2>&1; then
  stale+=("vendored-generated/builtin_manifest.generated.rs" "src/builtins/helpers/runtime-module-manifest.cjs")
fi

# --- bundle builders (write to scratch, diff against committed) -------------
bun run build:builtins --out-dir "$scratch/builtins" >/dev/null 2>&1
if ! diff -r "vendored-generated/builtins" "$scratch/builtins" >/dev/null 2>&1; then
  stale+=("vendored-generated/builtins/*.js")
fi

bun run build:runtime --out "$scratch/embedded_runtime_bundle.js" >/dev/null 2>&1
if ! diff "vendored-generated/embedded_runtime_bundle.js" "$scratch/embedded_runtime_bundle.js" >/dev/null 2>&1; then
  stale+=("vendored-generated/embedded_runtime_bundle.js")
fi

if [ "${#stale[@]}" -eq 0 ]; then
  echo "Generated artifacts are up to date."
  exit 0
fi

echo "error: committed generated artifacts are stale:" >&2
for path in "${stale[@]}"; do
  echo "  - $path" >&2
done
echo >&2
echo "Refresh them with: bun run regenerate:vendored" >&2
exit 1
