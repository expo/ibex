#!/usr/bin/env bash
# Regenerate every committed generated artifact from its source authority.
# @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check — one command
# so an agent editing JS/builtins/capability-bit/runtime-identity sources does
# not have to remember which of the five generators to run.
#
# This is the opt-in, bun-mediated regeneration path. Per LLP 0005/0006 it is
# NOT part of the hermetic `cargo build`; the full build.rs-mediated refresh is
# still `bun run refresh:vendored`. `bun run check:drift` enforces that this
# command and refresh:vendored produce the same bytes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun is required to regenerate vendored artifacts (run bun install)" >&2
  exit 1
fi

# Order matters: identity/capability/module manifests are inputs the builtin and
# runtime bundles compile against. Flags live only in package.json (one source
# of truth, shared with check:drift).
bun run generate:capability-bits
bun run generate:identity
bun run generate:modules
bun run build:builtins
bun run build:runtime

echo "Regenerated vendored artifacts. Review with: git status vendored-generated/ src/identity_generated.rs packages/ibex-runtime-js/src" >&2
