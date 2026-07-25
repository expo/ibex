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
bun run generate:repl-surface
bun run generate:session-constants
bun run generate:interrupt-machine
bun run generate:session-semantics
bun run generate:vfs-error-union
bun run generate:root-global-dispositions
# The private CapSec registry authenticates the generated WebGPU production
# plan, so refresh the wrapper inputs and plan before deriving the registry.
bun run generate:webgpu-test-wrapper
bun run generate:webgpu-production-plan
# @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
# source-derived registry must exist before the contract binds its digests.
bun run generate:capsec-registry
bun run generate:runtime-environment-inventory
bun run generate:host-task-ingress-inventory
bun run generate:capsec-contract
bun run generate:capsec-runtime-projection
bun run generate:compiled-environment-profile
bun run generate:oxc-retirement-manifest
bun run generate:identity
bun run generate:import-grant-keys
bun run generate:modules
bun run generate:webgpu-production-codec-corpus
bun run generate:module-transform-config
# Postcondition: the module generator writes both the JS runtime manifest and
# the Rust builtin manifest. Check immediately so a future package-script edit
# cannot silently stop refreshing one side.
bun run generate:modules --check
bun run check:capsec-runtime-projection
bun run check:compiled-environment-profile
bun run check:oxc-retirement
bun run check:module-transform-config
bun run build:builtins
bun run build:runtime:core
bun run build:runtime:webgpu
bun run generate:vendored-fingerprint

echo "Regenerated vendored artifacts. Review with: git status capsec/ vendored-generated/ tests/fixtures/ src/builtins/helpers/runtime-module-manifest.cjs src/identity_generated.rs packages/ibex-runtime-js/src" >&2
