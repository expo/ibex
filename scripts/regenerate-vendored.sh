#!/usr/bin/env bash
# Regenerate every committed generated artifact from its source authority.
# @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check — one command
# so an agent editing JS/builtins/capability-bit/runtime-identity sources does
# not have to remember each generator and fingerprint step.
#
# This is the opt-in, bun-mediated regeneration path. Per LLP 0005/0006 it is
# NOT part of the hermetic `cargo build`; the full build.rs-mediated refresh is
# still `bun run refresh:vendored`. Capability-contract review artifacts are
# Bun-only and are refreshed here as part of the same human-facing command;
# `bun run check:drift` verifies both them and the vendored build outputs.
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
# @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
# source-derived registry must exist before the contract binds its digests.
bun run generate:capsec-registry
bun run generate:capsec-contract
bun run generate:identity
bun run generate:modules
# Postcondition: the module generator writes both the JS runtime manifest and
# the Rust builtin manifest. Check immediately so a future package-script edit
# cannot silently stop refreshing one side.
bun run generate:modules --check
bun run build:builtins
bun run build:runtime
bun run generate:vendored-fingerprint

echo "Regenerated vendored artifacts. Review with: git status capsec/ vendored-generated/ src/builtins/helpers/runtime-module-manifest.cjs src/identity_generated.rs packages/ibex-runtime-js/src" >&2
